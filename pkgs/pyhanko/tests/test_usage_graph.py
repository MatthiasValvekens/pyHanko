import gc
import glob
import os
import random
import weakref
from collections import defaultdict
from io import BytesIO

import pytest
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError, PdfReadError
from pyhanko.pdf_utils.reader import (
    HistoricalResolver,
    PdfFileReader,
    RawPdfPath,
)
from pyhanko.pdf_utils.writer import PdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.diff_analysis.rules_api import RelativeContext
from pyhanko.sign.diff_analysis.usage_graph import (
    SATURATION_CAP,
    UsageGraph,
    _DominatorTree,
    _immediate_dominators,
    build_usage_graph,
)
from pyhanko_testing_commons.test_data.samples import (
    MINIMAL,
    MINIMAL_TWO_FIELDS_TAGGED,
    PDF_DATA_DIR,
    SIMPLE_FORM,
    simple_page,
)
from pyhanko_testing_commons.test_utils.signing_commons import SELF_SIGN

FIXTURES = sorted(
    glob.glob(os.path.join(PDF_DATA_DIR, '**', '*.pdf'), recursive=True)
)


def _legacy_paths(
    resolver: HistoricalResolver,
) -> dict[generic.Reference, set[RawPdfPath]]:
    resolver._load_reverse_xref_cache()
    return resolver._indirect_object_access_cache or {}


def _relative_view(resolver: HistoricalResolver, path: RawPdfPath):
    # resolve every hop in the revision under test
    anchor, relative = None, ()
    current = resolver.trailer_view
    for position, key in enumerate(path):
        following = current.raw_get(key)
        if isinstance(following, generic.IndirectObject):
            if position == len(path) - 1:
                return anchor, (*relative, key)
            anchor, relative = following.reference, ()
            current = resolver(following.reference)
        else:
            relative = (*relative, key)
            current = following
    raise AssertionError  # pragma: nocover


def _group_key(group: RelativeContext):
    anchor = group.anchor
    ident = (
        None
        if isinstance(anchor, generic.TrailerReference)
        else (anchor.idnum, anchor.generation)
    )
    return ident, tuple(group.relative_path)


def _legacy_group_key(resolver, path):
    anchor, relative = _relative_view(resolver, path)
    ident = None if anchor is None else (anchor.idnum, anchor.generation)
    return ident, relative


def _is_cyclic(graph: UsageGraph, ref: generic.Reference) -> bool:
    return any(info.cyclic for info in graph.inbound_groups(ref).values())


def _compare_with_enumeration(resolver: HistoricalResolver):
    legacy = _legacy_paths(resolver)
    graph = build_usage_graph(resolver)
    page_tree = resolver._load_tree_index().page_tree_nodes
    for ref in set(legacy) | set(graph._copies):
        paths = legacy.get(ref, set())
        groups = graph.inbound_groups(ref)
        assert {_group_key(g) for g in groups} == {
            _legacy_group_key(resolver, p) for p in paths
        }, ref
        if _is_cyclic(graph, ref):
            assert graph.usage_count(ref) == SATURATION_CAP
        elif ref in page_tree:
            assert graph.usage_count(ref) >= len(paths), ref
            assert set(graph.iter_paths(ref)) == paths, ref
        else:
            assert graph.usage_count(ref) == len(paths), ref


@pytest.mark.parametrize(
    'fname', FIXTURES, ids=[os.path.basename(f) for f in FIXTURES]
)
def test_counts_and_groups_match_enumeration(fname):
    with open(fname, 'rb') as inf:
        try:
            r = PdfFileReader(BytesIO(inf.read()), strict=False)
            revisions = r.xrefs.total_revisions
        except PdfError:
            pytest.skip('unreadable')
    for revision in range(revisions):
        try:
            resolver = r.get_historical_resolver(revision)
            _legacy_paths(resolver)
        except (PdfError, AssertionError, TypeError):
            # the legacy enumeration can't deal with every broken file
            continue
        _compare_with_enumeration(resolver)


# Document construction helpers


def _obj(entries: dict[str, object]) -> generic.DictionaryObject:
    return generic.DictionaryObject(
        {generic.pdf_name(k): v for k, v in entries.items()}
    )


def _arr(*items) -> generic.ArrayObject:
    return generic.ArrayObject(items)


def _build(populate, n_pages: int = 1) -> HistoricalResolver:
    w = PdfFileWriter()
    pages = [w.insert_page(simple_page(w, f'Page {i}')) for i in range(n_pages)]
    populate(w, pages)
    out = BytesIO()
    w.write(out)
    r = PdfFileReader(out)
    return r.get_historical_resolver(r.xrefs.total_revisions - 1)


def _ref_at(resolver: HistoricalResolver, *path) -> generic.Reference:
    return RawPdfPath(*path).access_reference_on(resolver.trailer_view)


def _paths_to(resolver, ref) -> set[RawPdfPath]:
    return set(build_usage_graph(resolver).iter_paths(ref))


def _first_page_contents_paths(resolver) -> set[RawPdfPath]:
    contents = _ref_at(resolver, '/Root', '/Pages', '/Kids', 0, '/Contents')
    return _paths_to(resolver, contents)


FIRST_PAGE_CONTENTS_PATH = RawPdfPath(
    '/Root', '/Pages', '/Kids', 0, '/Contents'
)


# Page tree


def test_page_tree_canonical_entry_only():
    def populate(w, pages):
        for src in pages:
            for dest in pages:
                if dest != src:
                    link = w.add_object(
                        _obj(
                            {
                                '/Type': generic.pdf_name('/Annot'),
                                '/A': _obj({'/D': _arr(dest)}),
                            }
                        )
                    )
                    w.register_annotation(src, link)

    resolver = _build(populate, n_pages=6)
    assert _first_page_contents_paths(resolver) == {FIRST_PAGE_CONTENTS_PATH}
    graph = build_usage_graph(resolver)
    pages = _ref_at(resolver, '/Root', '/Pages')
    page = _ref_at(resolver, '/Root', '/Pages', '/Kids', 1)
    assert len(list(graph.iter_paths(pages))) == 1
    # one canonical path, plus one per link to the page
    assert len(list(graph.iter_paths(page))) == 1 + 5 * 1


def test_page_tree_not_reentered_via_foreign_kids():
    def populate(w, pages):
        for p in pages:
            p.get_object()['/Foo'] = _obj(
                {'/Kids': _arr(*(q for q in pages if q != p))}
            )

    resolver = _build(populate, n_pages=7)
    assert _first_page_contents_paths(resolver) == {FIRST_PAGE_CONTENTS_PATH}


def test_page_tree_root_not_reentered_from_outside():
    def populate(w, pages):
        w.root['/Foo'] = w.root.raw_get('/Pages')

    resolver = _build(populate, n_pages=4)
    assert _first_page_contents_paths(resolver) == {FIRST_PAGE_CONTENTS_PATH}
    pages = _ref_at(resolver, '/Root', '/Pages')
    assert _paths_to(resolver, pages) == {
        RawPdfPath('/Root', '/Pages'),
        RawPdfPath('/Root', '/Foo'),
    }


def test_page_tree_direct_root_node():
    def populate(w, pages):
        w.root['/Pages'] = w.root['/Pages']

    resolver = _build(populate, n_pages=4)
    assert _first_page_contents_paths(resolver) == {FIRST_PAGE_CONTENTS_PATH}


def test_page_tree_indirect_kids_array_is_still_canonical():
    def populate(w, pages):
        pages_dict = w.root['/Pages']
        pages_dict['/Kids'] = w.add_object(pages_dict['/Kids'])

    resolver = _build(populate, n_pages=3)
    assert _first_page_contents_paths(resolver) == {FIRST_PAGE_CONTENTS_PATH}
    _compare_with_enumeration(resolver)


def test_page_tree_nested_nodes_are_canonical_once():
    def populate(w, pages):
        inner = w.add_object(
            _obj(
                {
                    '/Type': generic.pdf_name('/Pages'),
                    '/Kids': _arr(*pages),
                    '/Count': generic.NumberObject(len(pages)),
                }
            )
        )
        for page in pages:
            page.get_object()['/Parent'] = inner
        pages_dict = w.root['/Pages']
        pages_dict['/Kids'] = _arr(inner)

    resolver = _build(populate, n_pages=3)
    contents = _ref_at(
        resolver, '/Root', '/Pages', '/Kids', 0, '/Kids', 1, '/Contents'
    )
    assert _paths_to(resolver, contents) == {
        RawPdfPath('/Root', '/Pages', '/Kids', 0, '/Kids', 1, '/Contents')
    }
    _compare_with_enumeration(resolver)


# Structure tree


def _tagged_document(populate):
    def _populate(w, pages):
        elem = w.allocate_placeholder()
        child = w.allocate_placeholder()
        str_root = w.add_object(
            _obj(
                {
                    '/Type': generic.pdf_name('/StructTreeRoot'),
                    '/K': _arr(elem),
                }
            )
        )
        w.add_object(
            _obj(
                {
                    '/Type': generic.pdf_name('/StructElem'),
                    '/S': generic.pdf_name('/Document'),
                    '/P': str_root,
                    '/K': _arr(child),
                }
            ),
            idnum=elem.idnum,
        )
        w.add_object(
            _obj(
                {
                    '/Type': generic.pdf_name('/StructElem'),
                    '/S': generic.pdf_name('/P'),
                    '/P': elem,
                    '/Pg': pages[0],
                }
            ),
            idnum=child.idnum,
        )
        w.root['/StructTreeRoot'] = str_root
        populate(w, pages, str_root, elem, child)

    return _build(_populate)


def test_struct_tree_context_skips_p():
    resolver = _tagged_document(lambda *_: None)
    graph = build_usage_graph(resolver)
    str_root = _ref_at(resolver, '/Root', '/StructTreeRoot')
    elem = _ref_at(resolver, '/Root', '/StructTreeRoot', '/K', 0)
    assert _paths_to(resolver, str_root) == {
        RawPdfPath('/Root', '/StructTreeRoot')
    }
    assert _paths_to(resolver, elem) == {
        RawPdfPath('/Root', '/StructTreeRoot', '/K', 0)
    }
    # /Pg is a regular reference, so the page is reachable through it
    page = _ref_at(resolver, '/Root', '/Pages', '/Kids', 0)
    assert len(graph.inbound_groups(page)) == 2


def test_p_outside_struct_tree_is_followed():
    def populate(w, pages, str_root, elem, child):
        w.root['/Foo'] = _obj({'/P': child})

    resolver = _tagged_document(populate)
    child = _ref_at(resolver, '/Root', '/StructTreeRoot', '/K', 0, '/K', 0)
    assert _paths_to(resolver, child) == {
        RawPdfPath('/Root', '/StructTreeRoot', '/K', 0, '/K', 0),
        RawPdfPath('/Root', '/Foo', '/P'),
    }


def test_struct_elem_entered_from_outside_is_sink():
    def populate(w, pages, str_root, elem, child):
        w.root['/Foo'] = elem

    resolver = _tagged_document(populate)
    graph = build_usage_graph(resolver)
    elem = _ref_at(resolver, '/Root', '/StructTreeRoot', '/K', 0)
    child = _ref_at(resolver, '/Root', '/StructTreeRoot', '/K', 0, '/K', 0)
    assert _paths_to(resolver, elem) == {
        RawPdfPath('/Root', '/StructTreeRoot', '/K', 0),
        RawPdfPath('/Root', '/Foo'),
    }
    # the walk stops at the element when entering from outside
    assert _paths_to(resolver, child) == {
        RawPdfPath('/Root', '/StructTreeRoot', '/K', 0, '/K', 0)
    }
    assert graph.usage_count(child) == 1
    _compare_with_enumeration(resolver)


def test_widget_in_both_contexts():
    r = PdfFileReader(BytesIO(MINIMAL_TWO_FIELDS_TAGGED))
    resolver = r.get_historical_resolver(0)
    graph = build_usage_graph(resolver)
    # one use from the AcroForm hierarchy, one from the page's /Annots,
    # and one from the structure tree
    assert graph.usage_count(generic.Reference(7, 0, resolver)) == 3
    _compare_with_enumeration(resolver)


# Dead edges and cycles


def _signed_with_field_lock() -> PdfFileReader:
    w = IncrementalPdfFileWriter(BytesIO(SIMPLE_FORM))
    fields.append_signature_field(
        w,
        fields.SigFieldSpec(
            'SigNew',
            box=(10, 74, 140, 134),
            field_mdp_spec=fields.FieldMDPSpec(fields.FieldMDPAction.ALL),
            doc_mdp_update_value=fields.MDPPerm.FILL_FORMS,
        ),
    )
    out = signers.sign_pdf(
        w,
        signers.PdfSignatureMetadata(field_name='SigNew', certify=True),
        signer=SELF_SIGN,
    )
    return PdfFileReader(out)


def test_fieldmdp_data_backref_is_dead_edge():
    r = _signed_with_field_lock()
    resolver = r.get_historical_resolver(r.xrefs.total_revisions - 1)
    graph = build_usage_graph(resolver)
    # The signature's /Reference entry has a /Data entry that refers back to
    # the catalog, which would put the entire form into a cycle.
    sig_dict = r.embedded_signatures[0].sig_object
    assert any(
        ref_dict.get('/Data') is not None
        and ref_dict.raw_get('/Data').reference == resolver.root_ref
        for ref_dict in sig_dict['/Reference']
    )
    assert all(
        group.relative_path.path[-1] != '/Data'
        for group in graph.inbound_groups(resolver.root_ref)
    )
    assert not any(graph._cyclic)
    _compare_with_enumeration(resolver)


def test_self_reference_ignored():
    def populate(w, pages):
        field = w.allocate_placeholder()
        w.add_object(
            _obj(
                {
                    '/FT': generic.pdf_name('/Btn'),
                    '/A': _obj(
                        {
                            '/S': generic.pdf_name('/ResetForm'),
                            '/Fields': _arr(field),
                        }
                    ),
                }
            ),
            idnum=field.idnum,
        )
        w.root['/Foo'] = _arr(field)

    resolver = _build(populate)
    field = _ref_at(resolver, '/Root', '/Foo', 0)
    graph = build_usage_graph(resolver)
    assert _paths_to(resolver, field) == {RawPdfPath('/Root', '/Foo', 0)}
    assert graph.usage_count(field) == 1
    _compare_with_enumeration(resolver)


def _outline_document(w, pages):
    items = [w.allocate_placeholder() for _ in range(3)]
    outlines = w.add_object(
        _obj(
            {
                '/Type': generic.pdf_name('/Outlines'),
                '/First': items[0],
                '/Last': items[2],
                '/Count': generic.NumberObject(3),
            }
        )
    )
    for ix, item in enumerate(items):
        entries = {
            '/Title': generic.TextStringObject(f'Item {ix}'),
            '/Parent': outlines,
            '/A': w.add_object(
                _obj({'/S': generic.pdf_name('/GoTo'), '/D': _arr(pages[0])})
            ),
        }
        if ix > 0:
            entries['/Prev'] = items[ix - 1]
        if ix < 2:
            entries['/Next'] = items[ix + 1]
        w.add_object(_obj(entries), idnum=item.idnum)
    w.root['/Outlines'] = outlines


def test_irreducible_outline_cycle_saturates():
    resolver = _build(_outline_document)
    graph = build_usage_graph(resolver)
    outlines = _ref_at(resolver, '/Root', '/Outlines')
    first = _ref_at(resolver, '/Root', '/Outlines', '/First')
    action = _ref_at(resolver, '/Root', '/Outlines', '/First', '/A')

    assert not _is_cyclic(graph, outlines)
    assert graph.usage_count(outlines) == 1
    for item_or_action in (first, action):
        assert _is_cyclic(graph, item_or_action)
        assert graph.usage_count(item_or_action) == SATURATION_CAP
    # inbound groups stay exact
    assert len(graph.inbound_groups(first)) == 2
    assert len(graph.inbound_groups(action)) == 1
    _compare_with_enumeration(resolver)


def test_article_bead_ring_saturates():
    def populate(w, pages):
        second_page = w.insert_page(simple_page(w, 'Other page'))
        pages = [*pages, second_page]
        beads = [w.allocate_placeholder() for _ in range(3)]
        thread = w.add_object(
            _obj(
                {
                    '/F': beads[0],
                    '/I': _obj({'/Title': generic.TextStringObject('t')}),
                }
            )
        )
        for ix, bead in enumerate(beads):
            w.add_object(
                _obj(
                    {
                        '/T': thread,
                        '/N': beads[(ix + 1) % 3],
                        '/V': beads[(ix - 1) % 3],
                        '/P': pages[ix % 2],
                        '/R': _arr(*map(generic.NumberObject, (0, 0, 5, 5))),
                    }
                ),
                idnum=bead.idnum,
            )
        pages[0].get_object()['/B'] = _arr(beads[0], beads[1])
        pages[1].get_object()['/B'] = _arr(beads[2])
        w.root['/Threads'] = _arr(thread)

    resolver = _build(populate)
    graph = build_usage_graph(resolver)
    bead = _ref_at(resolver, '/Root', '/Threads', 0, '/F')
    assert _is_cyclic(graph, bead)
    assert graph.usage_count(bead) == SATURATION_CAP
    assert len(graph.inbound_groups(bead)) >= 3
    _compare_with_enumeration(resolver)


# Random graphs

RANDOM_KEYS = ['/A', '/B', '/C', '/Parent', '/P', '/K', '/Kids', '/Obj']


def _random_document(
    rng: random.Random, with_trees: bool
) -> HistoricalResolver:
    def populate(w, pages):
        nodes = [_obj({}) for _ in range(rng.randint(2, 12))]
        pool = [w.add_object(node) for node in nodes]
        if with_trees:
            str_root = w.add_object(
                _obj({'/Type': generic.pdf_name('/StructTreeRoot')})
            )
            elems = []
            for _ in range(rng.randint(1, 5)):
                parent = rng.choice([str_root, *elems])
                elem = w.add_object(
                    _obj(
                        {
                            '/Type': generic.pdf_name('/StructElem'),
                            '/P': parent,
                        }
                    )
                )
                parent_dict = parent.get_object()
                parent_dict.setdefault('/K', _arr()).append(elem)
                elems.append(elem)
            w.root['/StructTreeRoot'] = str_root
            pool += [str_root, *elems, w.root.raw_get('/Pages'), *pages]

        def value(depth: int = 0):
            kind = rng.random()
            if kind < 0.45:
                return rng.choice(pool)
            elif kind < 0.65:
                return _arr(
                    *(rng.choice(pool) for _ in range(rng.randint(1, 3)))
                )
            elif kind < 0.8 and depth < 2:
                return _obj({rng.choice(RANDOM_KEYS): value(depth + 1)})
            return generic.NumberObject(rng.randint(0, 9))

        for node in nodes:
            for _ in range(rng.randint(1, 3)):
                node[generic.pdf_name(rng.choice(RANDOM_KEYS))] = value()
        w.root['/Foo'] = pool[0]
        if rng.random() < 0.5:
            w.root['/Bar'] = rng.choice(pool)

    return _build(populate, n_pages=rng.randint(1, 3))


def _brute_force_paths(resolver: HistoricalResolver):
    paths = defaultdict(set)

    def walk(obj, path, seen):
        if isinstance(obj, generic.IndirectObject):
            ref = obj.reference
            if ref in seen:
                return
            paths[ref].add(RawPdfPath(*path))
            seen = seen | {ref}
            obj = resolver(ref)
        if isinstance(obj, generic.DictionaryObject):
            for key, value in obj.items():
                if key != '/Parent':
                    walk(value, (*path, key), seen)
        elif isinstance(obj, generic.ArrayObject):
            for ix, value in enumerate(obj):
                walk(value, (*path, ix), seen)

    walk(resolver.trailer_view, (), frozenset())
    return paths


@pytest.mark.parametrize('seed', range(300))
def test_random_graphs_match_brute_force_enumeration(seed):
    resolver = _random_document(random.Random(seed), with_trees=False)
    graph = build_usage_graph(resolver)
    expected = _brute_force_paths(resolver)
    assert set(graph._copies) == set(expected)
    for ref, paths in expected.items():
        assert set(graph.iter_paths(ref)) == paths
        if _is_cyclic(graph, ref):
            assert graph.usage_count(ref) == SATURATION_CAP
        else:
            assert graph.usage_count(ref) == len(paths)
        for path in paths:
            assert graph.is_enumerated_path(path, ref)
            group = graph.last_edge(path)
            assert group in graph.inbound_groups(ref)
            # witnesses are for display purposes and may revisit the target
            witness = graph.witness(group)
            assert witness.path[-len(group.relative_path) :] == (
                group.relative_path.path
            )


@pytest.mark.parametrize('seed', range(300))
def test_random_graphs_with_trees_match_legacy_enumeration(seed):
    resolver = _random_document(random.Random(seed), with_trees=True)
    _compare_with_enumeration(resolver)


def _brute_force_dominators(
    successors: list[list[int]], root: int
) -> list[set[int]]:
    def reachable_without(removed: int) -> set[int]:
        if removed == root:
            return set()
        seen = {root}
        todo = [root]
        while todo:
            for succ in successors[todo.pop()]:
                if succ != removed and succ not in seen:
                    seen.add(succ)
                    todo.append(succ)
        return seen

    reachable = reachable_without(-1)
    return [
        reachable - reachable_without(candidate)
        if candidate in reachable
        else set()
        for candidate in range(len(successors))
    ]


@pytest.mark.parametrize('seed', range(300))
def test_dominators_match_bruteforce(seed):
    rng = random.Random(seed)
    size = rng.randint(1, 14)
    successors = [
        [rng.randrange(size) for _ in range(rng.randint(0, 3))]
        for _ in range(size)
    ]
    idom = _immediate_dominators(successors, 0)
    tree = _DominatorTree(idom, 0)
    expected = _brute_force_dominators(successors, 0)
    for dominator in range(size):
        for node in range(size):
            if idom[node] == -1:
                continue
            assert tree.dominates(dominator, node) == (
                node in expected[dominator]
            ), (successors, dominator, node)


# Scalability


def _chain_document(length: int, doubling: bool):
    def populate(w, pages):
        current = w.add_object(_obj({'/Leaf': generic.NumberObject(0)}))
        for _ in range(length):
            entries = {'/A': current}
            if doubling:
                entries['/B'] = current
            current = w.add_object(_obj(entries))
        w.root['/Chain'] = current

    return _build(populate)


def _leaf_of_chain(resolver, length: int) -> generic.Reference:
    return _ref_at(resolver, '/Root', '/Chain', *(['/A'] * length))


def test_deep_chain_no_recursion():
    length = 5000
    resolver = _chain_document(length, doubling=False)
    graph = build_usage_graph(resolver)
    leaf = _leaf_of_chain(resolver, length)
    assert graph.usage_count(leaf) == 1
    (group,) = graph.inbound_groups(leaf)
    witness = graph.witness(group)
    assert len(witness) == length + 2
    assert graph.is_enumerated_path(witness, leaf)
    assert list(graph.iter_paths(leaf)) == [witness]


def test_doubling_chain_saturates():
    length = 2000
    resolver = _chain_document(length, doubling=True)
    graph = build_usage_graph(resolver)
    assert graph.usage_count(_ref_at(resolver, '/Root', '/Chain')) == 1
    assert graph.usage_count(_ref_at(resolver, '/Root', '/Chain', '/A')) == 2
    leaf = _leaf_of_chain(resolver, length)
    assert graph.usage_count(leaf) == SATURATION_CAP
    assert not _is_cyclic(graph, leaf)
    assert len(graph.inbound_groups(leaf)) == 2
    # one node per object (plus the trailer and the unrelated page objects)
    assert graph.node_count < length + 20


# Index pre-passes


@pytest.mark.parametrize(
    'fname, message',
    [
        ('circular-page-tree.pdf', 'Circular reference in page.*mapping'),
        (
            'struct-tree-circular-ref.pdf',
            'Circular reference in struct.*mapping',
        ),
    ],
)
def test_circular_trees_are_rejected(fname, message):
    with open(os.path.join(PDF_DATA_DIR, fname), 'rb') as inf:
        r = PdfFileReader(BytesIO(inf.read()))
    with pytest.raises(PdfReadError, match=message):
        build_usage_graph(r.get_historical_resolver(0))


def test_struct_tree_with_content_items_and_foreign_types():
    def populate(w, pages, str_root, elem, child):
        elem_dict = elem.get_object()
        elem_dict['/K'] = _arr(
            child,
            generic.NumberObject(3),
            _obj({'/Type': generic.pdf_name('/OBJR'), '/Obj': pages[0]}),
            w.add_object(_obj({'/Type': generic.pdf_name('/Other')})),
        )

    resolver = _tagged_document(populate)
    assert build_usage_graph(resolver)._struct_tree_nodes == {
        _ref_at(resolver, '/Root', '/StructTreeRoot', '/K', 0),
        _ref_at(resolver, '/Root', '/StructTreeRoot', '/K', 0, '/K', 0),
    }


# Queries


def test_graph_is_cached_per_resolver_without_keeping_it_alive():
    reader = PdfFileReader(BytesIO(MINIMAL))
    resolver = HistoricalResolver(reader, 0)
    graph = build_usage_graph(resolver)
    assert build_usage_graph(resolver) is graph
    probe = weakref.ref(resolver)
    del resolver, graph
    gc.collect()
    assert probe() is None


def test_replay_rejects_what_enumeration_would_not_produce():
    def populate(w, pages):
        foo = w.allocate_placeholder()
        shared = w.add_object(_obj({'/Next': foo}))
        w.add_object(_obj({'/A': shared}), idnum=foo.idnum)
        w.root['/Foo'] = foo
        w.root['/Bar'] = shared

    resolver = _build(populate)
    graph = build_usage_graph(resolver)
    foo = _ref_at(resolver, '/Root', '/Foo')
    shared = _ref_at(resolver, '/Root', '/Bar')
    good = RawPdfPath('/Root', '/Foo', '/A')
    assert graph.is_enumerated_path(good, shared)
    assert graph.is_enumerated_path(RawPdfPath('/Root', '/Bar', '/Next'), foo)
    assert not graph.is_enumerated_path(good, foo)
    assert not graph.is_enumerated_path(RawPdfPath(), foo)
    assert not graph.is_enumerated_path(RawPdfPath('/Root', '/Nope'), foo)
    assert not graph.is_enumerated_path(good + '/Nope', shared)
    # revisiting /Foo is not allowed
    assert not graph.is_enumerated_path(good + '/Next', foo)
    with pytest.raises(ValueError, match='not a path'):
        graph.last_edge(RawPdfPath('/Root', '/Nope'))


def test_witness_for_trailer_group():
    resolver = _build(lambda *_: None)
    graph = build_usage_graph(resolver)
    (group,) = graph.inbound_groups(resolver.root_ref)
    assert isinstance(group.anchor, generic.TrailerReference)
    assert graph.witness(group) == RawPdfPath('/Root')


def test_page_annotation_paths():
    annots = {}

    def populate(w, pages):
        def annot(name):
            annots[name] = w.add_object(
                _obj({'/Subtype': generic.pdf_name('/Link')})
            )
            return annots[name]

        pages[0].get_object()['/Annots'] = _arr(annot('direct'))
        pages[0].get_object()['/Bar'] = w.add_object(_arr(annot('wrong_key')))
        pages[0].get_object()['/Baz'] = _obj({'/x': annot('wrong_shape')})
        pages[1].get_object()['/Annots'] = w.add_object(_arr(annot('indirect')))
        pages[2].get_object()['/Annots'] = _obj({'/k': annot('not_an_index')})
        w.root['/Pages']['/Annots'] = _arr(annot('page_tree_root'))
        w.root['/Foo'] = w.add_object(_arr(annot('not_a_page')))

    resolver = _build(populate, n_pages=3)
    graph = build_usage_graph(resolver)
    ref = {name: obj.reference for name, obj in annots.items()}
    expected = {
        'direct': {RawPdfPath('/Root', '/Pages', '/Kids', 0, '/Annots', 0)},
        'indirect': {RawPdfPath('/Root', '/Pages', '/Kids', 1, '/Annots', 0)},
    }
    for name in annots:
        assert graph.page_annotation_paths(ref[name]) == expected.get(
            name, set()
        ), name


def test_page_annotation_paths_in_fixture():
    r = PdfFileReader(BytesIO(MINIMAL_TWO_FIELDS_TAGGED))
    resolver = r.get_historical_resolver(0)
    graph = build_usage_graph(resolver)
    assert graph.page_annotation_paths(generic.Reference(7, 0)) == {
        RawPdfPath('/Root', '/Pages', '/Kids', 0, '/Annots', 1)
    }
    assert graph.page_annotation_paths(generic.Reference(99, 0)) == set()


STRUCT_OBJ_PATH = RawPdfPath(
    '/Root', '/StructTreeRoot', '/K', 0, '/K', 0, '/K', '/Obj'
)


@pytest.mark.parametrize('indirect_objr', [False, True])
def test_struct_tree_obj_path(indirect_objr):
    def populate(w, pages, str_root, elem, child):
        objr = _obj({'/Type': generic.pdf_name('/OBJR'), '/Obj': pages[0]})
        child.get_object()['/K'] = w.add_object(objr) if indirect_objr else objr

    resolver = _tagged_document(populate)
    graph = build_usage_graph(resolver)
    page = _ref_at(resolver, '/Root', '/Pages', '/Kids', 0)
    assert graph.struct_tree_obj_path(page) == STRUCT_OBJ_PATH


def test_struct_tree_obj_path_in_fixture():
    r = PdfFileReader(BytesIO(MINIMAL_TWO_FIELDS_TAGGED))
    resolver = r.get_historical_resolver(0)
    graph = build_usage_graph(resolver)
    assert graph.struct_tree_obj_path(generic.Reference(7, 0)) == RawPdfPath(
        '/Root', '/StructTreeRoot', '/K', '/K', 0, '/K', 1, '/K', '/Obj'
    )
    assert graph.struct_tree_obj_path(generic.Reference(8, 0)) is None


def test_struct_tree_obj_path_requires_nesting_below_structure_tree_root():
    def populate(w, pages, str_root, elem, child):
        objr = _obj({'/Type': generic.pdf_name('/OBJR'), '/Obj': pages[0]})
        # too short, since it's a direct child of the root
        str_root.get_object()['/K'] = objr
        w.root['/Foo'] = _obj({'/K': _obj({'/Obj': pages[0]})})
        w.root['/Bar'] = _obj({'/K': w.add_object(_obj({'/Obj': pages[0]}))})
        w.root['/Baz'] = _obj({'/K': _arr(w.add_object(objr))})

    resolver = _tagged_document(populate)
    graph = build_usage_graph(resolver)
    page = _ref_at(resolver, '/Root', '/Pages', '/Kids', 0)
    assert graph.struct_tree_obj_path(page) is None


def test_struct_tree_obj_path_prefers_shortest_match():
    def populate(w, pages, str_root, elem, child):
        objr = _obj({'/Type': generic.pdf_name('/OBJR'), '/Obj': pages[0]})
        child.get_object()['/K'] = _arr(_obj({'/K': objr}))
        elem.get_object()['/K'].append(w.add_object(_obj({'/K': objr})))

    resolver = _tagged_document(populate)
    graph = build_usage_graph(resolver)
    page = _ref_at(resolver, '/Root', '/Pages', '/Kids', 0)
    assert graph.struct_tree_obj_path(page) == RawPdfPath(
        '/Root', '/StructTreeRoot', '/K', 0, '/K', 1, '/K', '/Obj'
    )


def test_struct_tree_obj_path_breaks_ties_deterministically():
    def populate(w, pages, str_root, elem, child):
        objr = _obj({'/Type': generic.pdf_name('/OBJR'), '/Obj': pages[0]})
        child.get_object()['/K'] = objr
        elem.get_object()['/K'].append(w.add_object(_obj({'/K': objr})))

    resolver = _tagged_document(populate)
    graph = build_usage_graph(resolver)
    page = _ref_at(resolver, '/Root', '/Pages', '/Kids', 0)
    assert graph.struct_tree_obj_path(page) == STRUCT_OBJ_PATH
