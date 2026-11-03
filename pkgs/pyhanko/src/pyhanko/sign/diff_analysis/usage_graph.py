"""
Internal API: a compact model of all the ways in which the objects of a
revision are used.

Not part of the public API, and subject to change without notice.

Difference analysis needs to know, for every object that is overridden after
signing, through which references it is reachable from the trailer. The number
of distinct paths can be exponential in the size of the document, so instead of
enumerating them, this module builds a *usage graph*.

The nodes of the graph are pairs of an object reference and a *state*. The
state records the few path-dependent facts that influence how the walk through
the document proceeds (is this the page tree entered through its canonical
path? are we inside the structure tree?). Edges correspond to indirect
references found in the object the edge originates from, and are labelled with
the keys and indices leading up to the reference.

Paths through the document correspond to walks through this graph.
Edges that can never be part of a walk that visits every object at most once
are discarded, which makes the number of walks reaching every node computable
in linear time (with saturation, see :data:`SATURATION_CAP`). The group of
edges ending in a given object and with a common last hop corresponds to a
:class:`~.rules_api.RelativeContext`.

All graph algorithms are iterative, so that deeply nested documents cannot
exhaust the interpreter's stack.
"""

import enum
import weakref
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass

from pyhanko.pdf_utils import generic, misc
from pyhanko.pdf_utils.reader import HistoricalResolver, RawPdfPath

from .rules_api import RelativeContext

__all__ = [
    'SATURATION_CAP',
    'GroupInfo',
    'UsageGraph',
    'build_usage_graph',
]

SATURATION_CAP = 2**32
"""
Upper limit for walk counts. Counts that reach this value are reported as
this value, and cannot be used to establish that all usages have been seen.
"""

_Label = tuple[str | int, ...]


@dataclass(frozen=True)
class GroupInfo:
    """
    Aggregate information about the usages of an object that share
    the same last hop.
    """

    count: int
    """
    Number of distinct paths that make up the group, saturated at
    :data:`SATURATION_CAP`. This is exact unless the object appears more than
    once on a path (which is only possible for some special objects such as
    the page tree and the document catalog), in which case it is an upper
    bound.
    """

    cyclic: bool
    """
    Whether any path in the group passes through a reference cycle.
    If this flag is set, the count is saturated.
    """


class _State(enum.Enum):
    TRAILER = enum.auto()
    ROOT_CANON = enum.auto()
    STR_CANON = enum.auto()
    PAGE_CANON = enum.auto()
    # an indirect object that sits in between two nodes of the page tree on
    # their canonical path (e.g. an indirect /Kids array)
    PAGE_PATH_CANON = enum.auto()
    STRUCT = enum.auto()
    NORMAL = enum.auto()
    SINK = enum.auto()


_STRUCT_PREFIXES: dict[_State, _Label] = {
    _State.TRAILER: ('/Root', '/StructTreeRoot', '/K'),
    _State.ROOT_CANON: ('/StructTreeRoot', '/K'),
    _State.STR_CANON: ('/K',),
}


def _in_struct_tree(state: _State, label: _Label) -> bool:
    if state == _State.STRUCT:
        return True
    prefix = _STRUCT_PREFIXES.get(state)
    return prefix is not None and label[: len(prefix)] == prefix


@dataclass(frozen=True)
class _NodeKey:
    # None for the trailer
    ref: generic.Reference | None
    state: _State
    # canonical page tree position, only for PAGE_PATH_CANON
    position: int | None = None


@dataclass(frozen=True, slots=True)
class _Edge:
    source: int
    label: _Label
    target: int


def _plain_ref(ref: generic.Reference) -> generic.Reference:
    # Don't hold on to the resolver, since the graph is cached in a weak
    # dictionary keyed by that resolver.
    return generic.Reference(ref.idnum, ref.generation)


class _PagePositions:
    """
    Trie of the canonical paths to page tree nodes, and of their prefixes.
    """

    def __init__(self):
        self._children: dict[tuple[int, str | int], int] = {}
        self._steps: list[tuple[int, str | int] | None] = [None]
        self.canonical: dict[generic.Reference, int] = {}

    def extend(self, position: int, elements: _Label) -> int:
        for element in elements:
            key = position, element
            try:
                position = self._children[key]
            except KeyError:
                self._children[key] = new_position = len(self._steps)
                self._steps.append(key)
                position = new_position
        return position

    def follow(self, position: int | None, elements: _Label) -> int | None:
        for element in elements:
            if position is None:
                return None
            position = self._children.get((position, element))
        return position

    def path_to(self, position: int) -> _Label:
        elements: list[str | int] = []
        step = self._steps[position]
        while step is not None:
            position, element = step
            elements.append(element)
            step = self._steps[position]
        return tuple(reversed(elements))


def _index_page_tree(old: HistoricalResolver) -> _PagePositions:
    pages = _PagePositions()
    root_position = pages.extend(0, ('/Root', '/Pages'))
    pages_ref = old.root.raw_get('/Pages')
    if isinstance(pages_ref, generic.IndirectObject):
        pages.canonical[_plain_ref(pages_ref.reference)] = root_position
    todo = [(pages_ref.get_object(), root_position)]
    while todo:
        node, position = todo.pop()
        kids_position = pages.extend(position, ('/Kids',))
        for ix, kid in enumerate(node['/Kids']):
            kid_position = pages.extend(kids_position, (ix,))
            if isinstance(kid, generic.IndirectObject):
                kid_ref = _plain_ref(kid.reference)
                if kid_ref in pages.canonical:
                    raise misc.PdfReadError(
                        "Circular reference in page tree in mapping stage"
                    )
                pages.canonical[kid_ref] = kid_position
            kid = kid.get_object()
            if kid.get('/Type', None) == '/Pages':
                todo.append((kid, kid_position))
    return pages


def _index_struct_tree(old: HistoricalResolver) -> frozenset[generic.Reference]:
    nodes: set[generic.Reference] = set()
    try:
        todo = [old.root.raw_get('/StructTreeRoot').get_object()]
    except KeyError:
        return frozenset()
    while todo:
        struct_elem = todo.pop()
        try:
            children = struct_elem['/K']
        except KeyError:
            continue
        # if there's only one child, /K need not be an array
        if not isinstance(children, generic.ArrayObject):
            children = (children,)
        for child in children:
            child_ref = None
            if isinstance(child, generic.IndirectObject):
                child_ref = _plain_ref(child.reference)
                child = child.get_object()
            # The /K entry can also refer to content items.
            # We don't care about those.
            if not isinstance(child, generic.DictionaryObject):
                continue
            # no /Type entry means /StructElem, according to the spec
            if child.get('/Type', '/StructElem') != '/StructElem':
                continue
            if child_ref is not None:
                if child_ref in nodes:
                    raise misc.PdfReadError(
                        "Circular reference in structure tree in mapping stage"
                    )
                nodes.add(child_ref)
            todo.append(child)
    return frozenset(nodes)


def _immediate_dominators(successors: list[list[int]], root: int) -> list[int]:
    """
    Lengauer-Tarjan with path compression, in iterative form.

    :return:
        For every node, its immediate dominator (the root for itself),
        or ``-1`` if the node is not reachable from the root.
    """
    dfn = [-1] * len(successors)
    vertex = [root]
    parent = [-1]
    dfn[root] = 0
    dfs_stack = [(root, iter(successors[root]))]
    while dfs_stack:
        node, successor_iter = dfs_stack[-1]
        for succ in successor_iter:
            if dfn[succ] == -1:
                dfn[succ] = len(vertex)
                vertex.append(succ)
                parent.append(dfn[node])
                dfs_stack.append((succ, iter(successors[succ])))
                break
        else:
            dfs_stack.pop()

    # from here on, vertices are identified by their DFS number
    count = len(vertex)
    predecessors: list[list[int]] = [[] for _ in range(count)]
    for num, node in enumerate(vertex):
        for succ in successors[node]:
            predecessors[dfn[succ]].append(num)

    semi = list(range(count))
    label = list(range(count))
    ancestor = [-1] * count
    idom = [0] * count
    bucket: list[list[int]] = [[] for _ in range(count)]

    def evaluate(v: int) -> int:
        if ancestor[v] == -1:
            return v
        chain = []
        top = v
        while ancestor[ancestor[top]] != -1:
            chain.append(top)
            top = ancestor[top]
        while chain:
            elem = chain.pop()
            anc = ancestor[elem]
            if semi[label[anc]] < semi[label[elem]]:
                label[elem] = label[anc]
            ancestor[elem] = ancestor[anc]
        return label[v]

    for w in range(count - 1, 0, -1):
        for v in predecessors[w]:
            u = evaluate(v)
            semi[w] = min(semi[w], semi[u])
        bucket[semi[w]].append(w)
        p = parent[w]
        ancestor[w] = p
        for v in bucket[p]:
            u = evaluate(v)
            idom[v] = u if semi[u] < semi[v] else p
        bucket[p].clear()
    for w in range(1, count):
        if idom[w] != semi[w]:
            idom[w] = idom[idom[w]]

    result = [-1] * len(successors)
    for num, node in enumerate(vertex):
        result[node] = vertex[idom[num]]
    result[root] = root
    return result


class _DominatorTree:
    def __init__(self, idom: list[int], root: int):
        children: list[list[int]] = [[] for _ in idom]
        for node, dominator in enumerate(idom):
            if dominator != -1 and node != root:
                children[dominator].append(node)
        self._pre = [-1] * len(idom)
        self._post = [-1] * len(idom)
        clock = 0
        self._pre[root] = clock
        stack = [(root, iter(children[root]))]
        while stack:
            node, child_iter = stack[-1]
            for child in child_iter:
                clock += 1
                self._pre[child] = clock
                stack.append((child, iter(children[child])))
                break
            else:
                clock += 1
                self._post[node] = clock
                stack.pop()

    def dominates(self, a: int, b: int) -> bool:
        return self._pre[a] <= self._pre[b] and self._post[b] <= self._post[a]


class UsageGraph:
    """
    Usage graph of a historical revision. Use :func:`build_usage_graph`
    to obtain one.

    The graph only contains the objects that can be reached from the trailer.
    """

    def __init__(self, old: HistoricalResolver):
        self._old = weakref.ref(old)
        self._pages = _index_page_tree(old)
        self._struct_tree_nodes = _index_struct_tree(old)
        self._root_position = self._pages.follow(0, ('/Root',))

        self._keys: list[_NodeKey] = []
        self._ids: dict[_NodeKey, int] = {}
        self._copies: dict[generic.Reference, list[int]] = {}
        self._out: list[list[_Edge]] = []
        self._build_product_graph(old)
        self._in: list[list[_Edge]] = [[] for _ in self._keys]
        self._walks: list[int] = []
        self._cyclic: list[bool] = []
        self._bfs_parent: list[_Edge | None] = []
        self._first_node: dict[generic.Reference, int] = {}
        self._remove_dead_edges()
        self._count_walks()
        self._label_indices: dict[int, tuple[dict[_Label, _Edge], int]] = {}
        self._group_cache: dict[
            generic.Reference, dict[RelativeContext, GroupInfo]
        ] = {}

    # Graph construction

    _ROOT = 0

    def _node_id(self, key: _NodeKey) -> tuple[int, bool]:
        try:
            return self._ids[key], False
        except KeyError:
            node_id = self._ids[key] = len(self._keys)
            self._keys.append(key)
            self._out.append([])
            if key.ref is not None:
                self._copies.setdefault(key.ref, []).append(node_id)
            return node_id, True

    def _position_of(self, key: _NodeKey) -> int | None:
        state = key.state
        if state == _State.TRAILER:
            return 0
        elif state == _State.ROOT_CANON:
            return self._root_position
        elif state == _State.PAGE_CANON:
            assert key.ref is not None
            return self._pages.canonical[key.ref]
        elif state == _State.PAGE_PATH_CANON:
            return key.position
        return None

    def _target_key(
        self, source: _NodeKey, label: _Label, target: generic.Reference
    ) -> _NodeKey:
        position = self._pages.follow(self._position_of(source), label)
        canonical_position = self._pages.canonical.get(target)
        if canonical_position is not None:
            if position == canonical_position:
                return _NodeKey(target, _State.PAGE_CANON)
            return _NodeKey(target, _State.SINK)
        in_struct = _in_struct_tree(source.state, label)
        if in_struct:
            return _NodeKey(target, _State.STRUCT)
        if target in self._struct_tree_nodes:
            return _NodeKey(target, _State.SINK)
        if source.state == _State.TRAILER and label == ('/Root',):
            return _NodeKey(target, _State.ROOT_CANON)
        if source.state == _State.ROOT_CANON and label == ('/StructTreeRoot',):
            return _NodeKey(target, _State.STR_CANON)
        if position is not None:
            return _NodeKey(target, _State.PAGE_PATH_CANON, position)
        return _NodeKey(target, _State.NORMAL)

    @staticmethod
    def _references_in(
        obj: generic.PdfObject, state: _State
    ) -> Iterator[tuple[_Label, generic.Reference]]:
        # Only direct objects are traversed: the labels describe how to get
        # from an indirect object (or the trailer) to a reference.
        todo: list[tuple[generic.PdfObject, _Label]] = [(obj, ())]
        while todo:
            current, label = todo.pop()
            if isinstance(current, generic.IndirectObject):
                yield label, _plain_ref(current.reference)
            elif isinstance(current, generic.DictionaryObject):
                skip_p = _in_struct_tree(state, label)
                entries = [
                    (key, value)
                    for key, value in current.items()
                    if key != '/Parent' and not (skip_p and key == '/P')
                ]
                todo.extend(
                    (value, label + (key,)) for key, value in reversed(entries)
                )
            elif isinstance(current, generic.ArrayObject):
                todo.extend(
                    (value, label + (ix,))
                    for ix, value in reversed(list(enumerate(current)))
                )

    def _build_product_graph(self, old: HistoricalResolver):
        root_key = _NodeKey(None, _State.TRAILER)
        assert self._node_id(root_key) == (self._ROOT, True)
        todo = [self._ROOT]
        while todo:
            node_id = todo.pop()
            key = self._keys[node_id]
            if key.state == _State.SINK:
                continue
            obj = old.trailer_view if key.ref is None else old(key.ref)
            edges = self._out[node_id]
            for label, target in self._references_in(obj, key.state):
                target_id, is_new = self._node_id(
                    self._target_key(key, label, target)
                )
                edges.append(_Edge(node_id, label, target_id))
                if is_new:
                    todo.append(target_id)

    # Dead edges, reachability, and walk counts

    def _remove_dead_edges(self):
        # An edge into a copy of R is useless if all walks reaching its source
        # pass through (a copy of) R already: it cannot be part of any
        # walk that visits R at most once.
        successors = [[e.target for e in edges] for edges in self._out]
        dominators = _DominatorTree(
            _immediate_dominators(successors, self._ROOT), self._ROOT
        )
        live_out: list[list[_Edge]] = [[] for _ in self._keys]
        for node_id, edges in enumerate(self._out):
            source_ref = self._keys[node_id].ref
            for edge in edges:
                target_ref = self._keys[edge.target].ref
                if target_ref == source_ref or any(
                    dominators.dominates(copy, node_id)
                    for copy in self._copies[target_ref]  # type: ignore
                ):
                    continue
                live_out[node_id].append(edge)

        # Dropping dead edges can disconnect parts of the graph. Those
        # parts are not part of any walk from the trailer.
        self._bfs_parent = [None] * len(self._keys)
        reachable = [False] * len(self._keys)
        reachable[self._ROOT] = True
        queue = deque([self._ROOT])
        while queue:
            node_id = queue.popleft()
            ref = self._keys[node_id].ref
            if ref is not None:
                self._first_node.setdefault(ref, node_id)
            for edge in live_out[node_id]:
                self._in[edge.target].append(edge)
                if not reachable[edge.target]:
                    reachable[edge.target] = True
                    self._bfs_parent[edge.target] = edge
                    queue.append(edge.target)
        self._out = [
            edges if reachable[node_id] else []
            for node_id, edges in enumerate(live_out)
        ]
        self._reachable = reachable

    def _count_walks(self):
        size = len(self._keys)
        walks = [0] * size
        walks[self._ROOT] = 1
        pending = [len(in_edges) for in_edges in self._in]
        queue = deque([self._ROOT])
        done = [False] * size
        while queue:
            node_id = queue.popleft()
            done[node_id] = True
            for edge in self._out[node_id]:
                target = edge.target
                walks[target] = min(
                    walks[target] + walks[node_id], SATURATION_CAP
                )
                pending[target] -= 1
                if not pending[target]:
                    queue.append(target)
        # whatever couldn't be ordered is part of, or downstream from, a cycle
        self._cyclic = [r and not d for r, d in zip(self._reachable, done)]
        self._walks = [
            SATURATION_CAP if cyclic else count
            for cyclic, count in zip(self._cyclic, walks)
        ]

    # Queries

    @property
    def node_count(self) -> int:
        """
        Number of nodes in the graph, including those that are not part of
        any path.
        """
        return len(self._keys)

    def _bind(self, ref: generic.Reference) -> generic.Reference:
        return generic.Reference(ref.idnum, ref.generation, self._old())

    def _anchor_of(self, node_id: int) -> generic.Dereferenceable:
        ref = self._keys[node_id].ref
        if ref is None:
            return generic.TrailerReference(self._old())
        return self._bind(ref)

    def _group_key(self, edge: _Edge) -> RelativeContext:
        return RelativeContext(
            self._anchor_of(edge.source), RawPdfPath(*edge.label)
        )

    def inbound_groups(
        self, ref: generic.Reference
    ) -> dict[RelativeContext, GroupInfo]:
        """
        Group the usages of an object by their last hop.

        :param ref:
            The object to look up.
        :return:
            A dictionary mapping each relative context in which the
            object is used to information about the usages in that
            context. The dictionary is empty if the object is not reachable.
        """
        plain = _plain_ref(ref)
        try:
            return self._group_cache[plain]
        except KeyError:
            pass
        counts: dict[RelativeContext, int] = {}
        cyclic: dict[RelativeContext, bool] = {}
        for copy in self._copies.get(plain, ()):
            for edge in self._in[copy]:
                group = self._group_key(edge)
                counts[group] = min(
                    counts.get(group, 0) + self._walks[edge.source],
                    SATURATION_CAP,
                )
                cyclic[group] = (
                    cyclic.get(group, False) or (self._cyclic[edge.source])
                )
        result = {
            group: GroupInfo(count=count, cyclic=cyclic[group])
            for group, count in counts.items()
        }
        self._group_cache[plain] = result
        return result

    def usage_count(self, ref: generic.Reference) -> int:
        """
        :return:
            The total number of usages of the object, saturated at
            :data:`SATURATION_CAP`.
        """
        return min(
            sum(info.count for info in self.inbound_groups(ref).values()),
            SATURATION_CAP,
        )

    def _label_index(self, node_id: int) -> tuple[dict[_Label, _Edge], int]:
        try:
            return self._label_indices[node_id]
        except KeyError:
            edges = self._out[node_id]
            index = {edge.label: edge for edge in edges}
            longest = max((len(label) for label in index), default=0)
            self._label_indices[node_id] = index, longest
            return index, longest

    def _replay(self, path: RawPdfPath) -> _Edge | None:
        """
        Follow a path from the trailer, and return its last edge if it is a
        walk that doesn't visit any reference twice.
        """
        keys = tuple(path)
        seen: set[generic.Reference] = set()
        node_id = self._ROOT
        last = None
        position = 0
        while position < len(keys):
            index, longest = self._label_index(node_id)
            for length in range(1, min(longest, len(keys) - position) + 1):
                last = index.get(keys[position : position + length])
                if last is not None:
                    break
            else:
                return None
            position += len(last.label)
            node_id = last.target
            ref = self._keys[node_id].ref
            assert ref is not None
            if ref in seen:
                return None
            seen.add(ref)
        return last

    def enumerated_last_edge(
        self, path: RawPdfPath, ref: generic.Reference
    ) -> RelativeContext | None:
        """
        Check whether a path is one of the usages of an object, and
        determine the group it belongs to.

        :param path:
            An absolute path.
        :param ref:
            The object that the path should lead to.
        :return:
            The group of the path if it leads from the trailer to a copy of
            the reference without visiting any object twice,
            ``None`` otherwise.
        """
        last = self._replay(path)
        if last is None or self._keys[last.target].ref != _plain_ref(ref):
            return None
        return self._group_key(last)

    def is_enumerated_path(
        self, path: RawPdfPath, ref: generic.Reference
    ) -> bool:
        """
        :return:
            ``True`` if the path is one of the usages of the object.
        """
        return self.enumerated_last_edge(path, ref) is not None

    def last_edge(self, path: RawPdfPath) -> RelativeContext:
        """
        :return:
            The group of the last hop of a path that is a walk through the
            graph.
        :raises ValueError:
            if the path doesn't correspond to a walk.
        """
        last = self._replay(path)
        if last is None:
            raise ValueError(f"{path} is not a path in the usage graph")
        return self._group_key(last)

    def _node_witness(self, node_id: int) -> _Label:
        labels: list[_Label] = []
        edge = self._bfs_parent[node_id]
        while edge is not None:
            labels.append(edge.label)
            edge = self._bfs_parent[edge.source]
        return tuple(element for label in reversed(labels) for element in label)

    def witness(self, group: RelativeContext) -> RawPdfPath:
        """
        Find a short path that leads to the given group.

        :param group:
            A group returned by :meth:`inbound_groups`.
        :return:
            An absolute path that ends with the group's last hop.
        """
        anchor = group.anchor
        if isinstance(anchor, generic.TrailerReference):
            prefix: _Label = ()
        else:
            assert isinstance(anchor, generic.Reference)
            prefix = self._node_witness(self._first_node[_plain_ref(anchor)])
        return RawPdfPath(*prefix, *group.relative_path)

    def iter_paths(self, ref: generic.Reference) -> Iterator[RawPdfPath]:
        """
        Enumerate all usages of an object as absolute paths.

        This is exponential in the worst case, and meant for testing only.
        """
        plain = _plain_ref(ref)
        for copy in self._copies.get(plain, ()):
            # walk backwards, keeping track of the references on the way
            on_path = {plain}
            edges_taken: list[_Edge] = []
            stack = [iter(self._in[copy])]
            while stack:
                for edge in stack[-1]:
                    source_ref = self._keys[edge.source].ref
                    if source_ref is None:
                        labels = [e.label for e in reversed(edges_taken)]
                        yield RawPdfPath(
                            *edge.label, *(x for lbl in labels for x in lbl)
                        )
                    elif source_ref not in on_path:
                        on_path.add(source_ref)
                        edges_taken.append(edge)
                        stack.append(iter(self._in[edge.source]))
                        break
                else:
                    stack.pop()
                    if edges_taken:
                        on_path.discard(
                            self._keys[edges_taken.pop().source].ref
                        )

    def page_annotation_paths(self, ref: generic.Reference) -> set[RawPdfPath]:
        """
        Find the paths through which an object is used as an annotation of a
        page tree node other than the root of the page tree.
        """
        result = set()
        for copy in self._copies.get(_plain_ref(ref), ()):
            for edge in self._in[copy]:
                for page, tail in self._annotation_hops(edge):
                    page_ref = self._keys[page].ref
                    assert page_ref is not None
                    canonical = self._pages.path_to(
                        self._pages.canonical[page_ref]
                    )
                    if '/Kids' in canonical:
                        result.add(RawPdfPath(*canonical, *tail))
        return result

    def _annotation_hops(self, edge: _Edge) -> Iterator[tuple[int, _Label]]:
        source = self._keys[edge.source]
        if source.state == _State.PAGE_CANON:
            if (
                len(edge.label) == 2
                and edge.label[0] == '/Annots'
                and isinstance(edge.label[1], int)
            ):
                yield edge.source, edge.label
        elif (
            source.state == _State.NORMAL
            and len(edge.label) == 1
            and isinstance(edge.label[0], int)
        ):
            # the annotation array is an indirect object
            for array_edge in self._in[edge.source]:
                array_owner = self._keys[array_edge.source]
                if (
                    array_owner.state == _State.PAGE_CANON
                    and array_edge.label == ('/Annots',)
                ):
                    yield array_edge.source, ('/Annots', *edge.label)

    def struct_tree_obj_path(self, ref: generic.Reference) -> RawPdfPath | None:
        """
        Find a path through which an object is used as the target of an object
        reference (``/OBJR``) in the structure tree.

        If there are several, the first one in a stable order is chosen.
        """
        candidates: list[RawPdfPath] = []
        for copy in self._copies.get(_plain_ref(ref), ()):
            for edge in self._in[copy]:
                if edge.label[-2:] == ('/K', '/Obj'):
                    candidates.append(
                        RawPdfPath(
                            *self._node_witness(edge.source), *edge.label
                        )
                    )
                elif edge.label == ('/Obj',):
                    # object reference is itself an indirect object
                    candidates.extend(
                        RawPdfPath(
                            *self._node_witness(parent.source),
                            *parent.label,
                            *edge.label,
                        )
                        for parent in self._in[edge.source]
                        if parent.label[-1:] == ('/K',)
                    )
        # Root.StructTreeRoot.K is three, and K.Obj at the end is another 2
        prefix = ('/Root', '/StructTreeRoot', '/K')
        valid = [c for c in candidates if len(c) >= 5 and c.path[:3] == prefix]
        return min(valid, key=lambda c: (len(c), c._tag()), default=None)


_GRAPH_CACHE: 'weakref.WeakKeyDictionary[HistoricalResolver, UsageGraph]' = (
    weakref.WeakKeyDictionary()
)


def build_usage_graph(old: HistoricalResolver) -> UsageGraph:
    """
    Obtain the usage graph of a revision. The result is cached per resolver.

    :param old:
        The revision to analyse.
    :return:
        A :class:`.UsageGraph`.
    """
    try:
        return _GRAPH_CACHE[old]
    except KeyError:
        graph = _GRAPH_CACHE[old] = UsageGraph(old)
        return graph
