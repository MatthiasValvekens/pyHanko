"""
Certificate policy processing for RFC 5280 path validation.

The algorithm implemented here is the one from :rfc:`5280`, with the policy
tree replaced by the policy graph of :rfc:`9618`. A policy graph represents
the same information as the policy tree it replaces, but its size is bounded
linearly by the number of policies and policy mappings in the path, whereas
the tree can grow exponentially in the length of the path.

This module is internal API.
"""

from collections import defaultdict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from asn1crypto import x509

from ._state import ValProcState
from .errors import PathValidationError
from .path import QualifiedPolicy

__all__ = [
    'ANY_POLICY',
    'AuthorityConstrainedPolicy',
    'PolicyGraph',
    'PolicyGraphNode',
    'apply_policy_mapping',
    'authority_constrained_policies',
    'enumerate_policy_mappings',
    'update_policy_graph',
    'user_constrained_policies',
]


ANY_POLICY = 'any_policy'
"""
Name under which ``asn1crypto`` reports the ``anyPolicy`` OID.
"""


Qualifiers = Iterable[x509.PolicyQualifierInfo]


class PolicyGraphNode:
    """
    A node in a :class:`.PolicyGraph`.

    Nodes are mutable, and are compared by identity.

    :param valid_policy:
        A policy OID that is valid for the path up to this node's depth.
    :param qualifier_set:
        The policy qualifiers associated with the valid policy in the
        certificate at this node's depth.
    :param expected_policy_set:
        The policy OIDs that would satisfy this policy in the next
        certificate in the path.
    :param depth:
        The depth of the node in the graph.
    """

    def __init__(
        self,
        valid_policy: str,
        qualifier_set: Qualifiers,
        expected_policy_set: set[str],
        depth: int,
    ):
        self.valid_policy = valid_policy
        self.qualifier_set = qualifier_set
        self.expected_policy_set = expected_policy_set
        self.depth = depth
        self.parents: list[PolicyGraphNode] = []
        """
        Nodes at depth ``depth - 1`` that this node was derived from.
        """

        self.children: list[PolicyGraphNode] = []
        """
        Nodes at depth ``depth + 1`` that were derived from this node.
        """

    def __repr__(self):  # pragma: nocover
        return (
            f"<PolicyGraphNode {self.valid_policy} at depth {self.depth} "
            f"expecting {sorted(self.expected_policy_set)}>"
        )

    def ancestors(self) -> Iterator['PolicyGraphNode']:
        """
        Enumerate all strict ancestors of this node.

        :return:
            A generator yielding policy graph nodes.
        """
        return _reachable(self.parents, lambda node: node.parents)

    def descendants(self) -> Iterator['PolicyGraphNode']:
        """
        Enumerate all strict descendants of this node.

        :return:
            A generator yielding policy graph nodes.
        """
        return _reachable(self.children, lambda node: node.children)


def _reachable(seeds, step) -> Iterator[PolicyGraphNode]:
    seen = {id(node): node for node in seeds}
    queue = list(seeds)
    while queue:
        node = queue.pop()
        yield node
        for next_node in step(node):
            if id(next_node) not in seen:
                seen[id(next_node)] = next_node
                queue.append(next_node)


class PolicyGraph:
    """
    Directed acyclic graph of certificate policies, as described in
    :rfc:`9618`. It replaces the ``valid_policy_tree`` of :rfc:`5280`.

    A newly instantiated graph consists of a single ``anyPolicy`` node at
    depth zero, i.e. the initial value of the ``valid_policy_graph`` state
    variable in the path validation algorithm.
    """

    def __init__(self) -> None:
        root = PolicyGraphNode(
            valid_policy=ANY_POLICY,
            qualifier_set=(),
            expected_policy_set={ANY_POLICY},
            depth=0,
        )
        self._levels: list[dict[str, PolicyGraphNode]] = [{ANY_POLICY: root}]

    @property
    def depth(self) -> int:
        """
        The depth of the deepest level in the graph that can contain nodes.
        """
        return len(self._levels) - 1

    def nodes_at_depth(self, depth: int) -> Iterable[PolicyGraphNode]:
        """
        Retrieve all nodes at a given depth.

        :param depth:
            The depth to look at.
        :return:
            The nodes at the given depth, or an empty collection if the depth
            is outside the graph's range.
        """
        if 0 <= depth < len(self._levels):
            return list(self._levels[depth].values())
        return ()

    def node_at(self, depth: int, valid_policy: str) -> PolicyGraphNode | None:
        """
        Retrieve the unique node with a given policy at a given depth, if any.

        :param depth:
            The depth to look at.
        :param valid_policy:
            The policy OID to look for.
        :return:
            The node in question, or ``None``.
        """
        if 0 <= depth < len(self._levels):
            return self._levels[depth].get(valid_policy)
        return None

    def expected_policies(self, depth: int) -> dict[str, list[PolicyGraphNode]]:
        """
        Index the nodes at a given depth by the policies they expect in the
        next certificate.

        :param depth:
            The depth to look at.
        :return:
            A dictionary mapping policy OIDs to the nodes expecting them.
        """
        result: dict[str, list[PolicyGraphNode]] = defaultdict(list)
        for node in self.nodes_at_depth(depth):
            for valid_policy in node.expected_policy_set:
                result[valid_policy].append(node)
        # not a defaultdict: a lookup miss must not conjure up a parentless node
        return dict(result)

    def add_node(
        self,
        depth: int,
        valid_policy: str,
        qualifier_set: Qualifiers,
        expected_policy_set: set[str],
        parents: Iterable[PolicyGraphNode],
    ) -> PolicyGraphNode:
        """
        Add a new node to the graph. There must not be a node with the same
        policy at the same depth already.

        :param depth:
            The depth at which to insert the node.
        :param valid_policy:
            The node's policy OID.
        :param qualifier_set:
            The node's policy qualifiers.
        :param expected_policy_set:
            The node's expected policy set.
        :param parents:
            The nodes at depth ``depth - 1`` to attach the new node to.
        :return:
            The newly created node.
        """
        while len(self._levels) <= depth:
            self._levels.append({})
        level = self._levels[depth]
        if valid_policy in level:
            raise ValueError(
                f"Policy {valid_policy} already occurs at depth {depth}"
            )
        node = PolicyGraphNode(
            valid_policy=valid_policy,
            qualifier_set=qualifier_set,
            expected_policy_set=expected_policy_set,
            depth=depth,
        )
        level[valid_policy] = node
        for parent in parents:
            parent.children.append(node)
            node.parents.append(parent)
        return node

    def delete_node(self, node: PolicyGraphNode):
        """
        Delete a node from the graph, together with the edges incident to it.
        Children that are left without any parents are deleted as well.

        Deleting a node that is not in the graph is a no-op.

        :param node:
            The node to delete.
        """
        level = self._levels[node.depth]
        if level.get(node.valid_policy) is not node:
            return
        del level[node.valid_policy]
        for parent in node.parents:
            parent.children.remove(node)
        orphans = []
        for child in node.children:
            child.parents.remove(node)
            if not child.parents:
                orphans.append(child)
        node.parents = []
        node.children = []
        for orphan in orphans:
            self.delete_node(orphan)

    def prune(self, max_depth: int) -> 'PolicyGraph | None':
        """
        Delete all childless nodes at depth ``max_depth`` or less, repeating
        until no such nodes remain.

        :param max_depth:
            The deepest level to prune.
        :return:
            The pruned graph, or ``None`` if the graph was emptied out.
        """
        candidates = [
            node
            for depth in range(min(max_depth, self.depth) + 1)
            for node in self.nodes_at_depth(depth)
            if not node.children
        ]
        while candidates:
            node = candidates.pop()
            parents = node.parents
            self.delete_node(node)
            candidates.extend(
                parent for parent in parents if not parent.children
            )
        if not self._levels[0]:
            return None
        return self


def update_policy_graph(
    certificate_policies: Iterable[x509.PolicyInformation],
    valid_policy_graph: PolicyGraph,
    depth: int,
    any_policy_uninhibited: bool,
) -> PolicyGraph | None:
    """
    Internal function to process a certificate policies extension into the
    policy graph, in accordance with step (d) of the algorithm in section
    6.1.3 of :rfc:`5280`, as replaced by section 5.3 of :rfc:`9618`.
    """

    graph = valid_policy_graph
    cert_any_policy: x509.PolicyInformation | None = None
    # the level above is not touched by any of the steps below, so it's safe
    # to index it once up front
    expected_policies = graph.expected_policies(depth - 1)

    # Step 2 d 1
    for policy in certificate_policies:
        policy_identifier = policy['policy_identifier'].native

        if policy_identifier == ANY_POLICY:
            cert_any_policy = policy
            continue

        if graph.node_at(depth, policy_identifier) is not None:
            # RFC 5280 § 4.2.1.4 forbids duplicate policy OIDs in a single
            # certificate policies extension; ignore repeat occurrences
            # rather than violate the uniqueness invariant of the graph.
            continue

        # Step 2 d 1 i
        parents = expected_policies.get(policy_identifier, [])
        if not parents:
            # Step 2 d 1 ii
            parent_any_policy = graph.node_at(depth - 1, ANY_POLICY)
            if parent_any_policy is None:
                continue
            parents = [parent_any_policy]
        graph.add_node(
            depth,
            policy_identifier,
            policy['policy_qualifiers'],
            {policy_identifier},
            parents,
        )

    # Step 2 d 2
    if cert_any_policy is not None and any_policy_uninhibited:
        any_policy_qualifiers = cert_any_policy['policy_qualifiers']
        for policy_identifier in sorted(expected_policies):
            if graph.node_at(depth, policy_identifier) is None:
                graph.add_node(
                    depth,
                    policy_identifier,
                    any_policy_qualifiers,
                    {policy_identifier},
                    expected_policies[policy_identifier],
                )

    # Step 2 d 3
    return graph.prune(depth - 1)


def enumerate_policy_mappings(
    mappings: Iterable[x509.PolicyMapping], proc_state: ValProcState
) -> dict[str, set[str]]:
    """
    Internal function to process policy mapping extension values into
    a Python dictionary mapping issuer domain policies to the corresponding
    policies in the subject policy domain.
    """
    policy_map: dict[str, set[str]] = defaultdict(set)
    for mapping in mappings:
        issuer_domain_policy = mapping['issuer_domain_policy'].native
        subject_domain_policy = mapping['subject_domain_policy'].native

        policy_map[issuer_domain_policy].add(subject_domain_policy)

        # Step 3 a
        if (
            issuer_domain_policy == ANY_POLICY
            or subject_domain_policy == ANY_POLICY
        ):
            raise PathValidationError.from_state(
                f"The path could not be validated because "
                f"{proc_state.describe_cert()} contains "
                f"a policy mapping for the \"any policy\"",
                proc_state,
            )

    return policy_map


def apply_policy_mapping(
    policy_map: dict[str, set[str]],
    valid_policy_graph: PolicyGraph,
    depth: int,
    policy_mapping_uninhibited: bool,
) -> PolicyGraph | None:
    """
    Internal function to apply the policy mapping to the current policy graph,
    in accordance with step (b) of the algorithm in section 6.1.4 of
    :rfc:`5280`, as replaced by section 5.4 of :rfc:`9618`.
    """

    graph: PolicyGraph | None = valid_policy_graph
    for issuer_domain_policy, subject_domain_policies in policy_map.items():
        if graph is None:
            break
        node = graph.node_at(depth, issuer_domain_policy)
        # Step 3 b 1
        if policy_mapping_uninhibited:
            if node is not None:
                node.expected_policy_set = subject_domain_policies
                continue
            # Step 3 b 2
            cert_any_policy = graph.node_at(depth, ANY_POLICY)
            if cert_any_policy is not None:
                graph.add_node(
                    depth,
                    issuer_domain_policy,
                    cert_any_policy.qualifier_set,
                    subject_domain_policies,
                    cert_any_policy.parents,
                )
        # Step 3 b 3
        else:
            if node is not None:
                graph.delete_node(node)
            graph = graph.prune(depth - 1)
    return graph


@dataclass(frozen=True)
class AuthorityConstrainedPolicy:
    """
    A policy that is valid for a certification path in the trust anchor's
    policy domain, together with its qualifiers and the policies in the
    end-entity certificate's domain that it corresponds to.
    """

    policy_oid: str
    """
    The policy OID, as understood by the trust anchor.
    """

    qualifiers: frozenset
    """
    Set of ``x509.PolicyQualifierInfo`` objects gathered from the policy's
    node in the policy graph, together with those of its ancestors and
    descendants.
    """

    issuer_domain_policy_oids: frozenset[str]
    """
    The policy OIDs at the end of the path that :attr:`policy_oid` was
    mapped to. If no policy mapping took place, this is a singleton
    containing :attr:`policy_oid` itself.
    """


def _collect_qualifiers(
    node: PolicyGraphNode,
) -> Iterator[tuple[bytes, x509.PolicyQualifierInfo]]:
    relatives = (node, *node.ancestors(), *node.descendants())
    for relative in relatives:
        for qualifier in relative.qualifier_set:
            yield qualifier.dump(), qualifier


def _valid_policy_node_set(
    valid_policy_graph: PolicyGraph, path_length: int
) -> Iterator[PolicyGraphNode]:
    # Step 4 g 2: nodes that branch off an anyPolicy node.
    #  In other words, find all policies that are valid and meaningful in
    #  the trust root(s) namespace. We don't care about what policy mapping
    #  transformed them into; that's taken care of by the validation
    #  algorithm.
    for depth in range(1, path_length + 1):
        for node in valid_policy_graph.nodes_at_depth(depth):
            if node.valid_policy == ANY_POLICY or len(node.parents) != 1:
                continue
            (parent,) = node.parents
            if parent.valid_policy == ANY_POLICY:
                yield node

    # Step 4 g 3
    final_any_policy = valid_policy_graph.node_at(path_length, ANY_POLICY)
    if final_any_policy is not None:
        yield final_any_policy


def authority_constrained_policies(
    valid_policy_graph: PolicyGraph | None, path_length: int
) -> dict[str, AuthorityConstrainedPolicy]:
    """
    Compute the authority-constrained policy set for a certification path,
    in accordance with steps (g)(1) through (g)(4) of the algorithm in section
    6.1.5 of :rfc:`5280`, as replaced by section 5.5 of :rfc:`9618`.

    :param valid_policy_graph:
        The policy graph at the end of path processing, or ``None`` if
        policy processing invalidated it.
    :param path_length:
        The length of the path, in the sense of :rfc:`5280` (i.e. excluding
        the trust anchor).
    :return:
        The authority-constrained policies, indexed by policy OID.
    """

    # Step 4 g 1
    if valid_policy_graph is None:
        return {}

    qualifiers: dict[str, dict[bytes, x509.PolicyQualifierInfo]] = defaultdict(
        dict
    )
    leaf_policies: dict[str, set[str]] = defaultdict(set)
    for node in _valid_policy_node_set(valid_policy_graph, path_length):
        # Step 4 g 4 ii
        qualifiers[node.valid_policy].update(_collect_qualifiers(node))
        # Step 4 g 4 i
        leaves = leaf_policies[node.valid_policy]
        if node.depth == path_length:
            leaves.add(node.valid_policy)
        leaves.update(
            descendant.valid_policy
            for descendant in node.descendants()
            if descendant.depth == path_length
        )

    return {
        policy_oid: AuthorityConstrainedPolicy(
            policy_oid=policy_oid,
            qualifiers=frozenset(qualifiers[policy_oid].values()),
            issuer_domain_policy_oids=frozenset(leaves),
        )
        for policy_oid, leaves in leaf_policies.items()
    }


def user_constrained_policies(
    valid_policy_graph: PolicyGraph | None,
    path_length: int,
    user_initial_policy_set: frozenset[str],
) -> frozenset[QualifiedPolicy]:
    """
    Compute the user-constrained policy set for a certification path, in
    accordance with step (g) of the algorithm in section 6.1.5 of
    :rfc:`5280`, as replaced by section 5.5 of :rfc:`9618`.

    The result is expressed as a set of :class:`.QualifiedPolicy` objects,
    with one entry for every pair of a user domain policy and a policy in the
    end-entity certificate's domain that it was mapped to.

    :param valid_policy_graph:
        The policy graph at the end of path processing, or ``None`` if
        policy processing invalidated it.
    :param path_length:
        The length of the path, in the sense of :rfc:`5280` (i.e. excluding
        the trust anchor).
    :param user_initial_policy_set:
        The policies that the user is willing to accept.
    :return:
        The user-constrained policies.
    """

    authority_constrained = authority_constrained_policies(
        valid_policy_graph, path_length
    )

    def _qualified(policy: AuthorityConstrainedPolicy):
        for issuer_domain_policy_oid in policy.issuer_domain_policy_oids:
            yield QualifiedPolicy(
                user_domain_policy_id=policy.policy_oid,
                issuer_domain_policy_id=issuer_domain_policy_oid,
                qualifiers=policy.qualifiers,
            )

    # Step 4 g 5
    if ANY_POLICY in user_initial_policy_set:
        return frozenset(
            qualified_policy
            for policy in authority_constrained.values()
            for qualified_policy in _qualified(policy)
        )

    # Step 4 g 6 i
    result = {
        qualified_policy
        for policy_oid, policy in authority_constrained.items()
        if policy_oid in user_initial_policy_set
        for qualified_policy in _qualified(policy)
    }

    # Step 4 g 6 ii: if the end of the path is still covered by anyPolicy,
    # expand it out into the acceptable policies that aren't accounted for yet
    try:
        wildcard = authority_constrained[ANY_POLICY]
    except KeyError:
        return frozenset(result)

    accounted_for = {policy.user_domain_policy_id for policy in result}
    result.update(
        QualifiedPolicy(
            user_domain_policy_id=policy_oid,
            issuer_domain_policy_id=policy_oid,
            qualifiers=wildcard.qualifiers,
        )
        for policy_oid in user_initial_policy_set - accounted_for
    )
    return frozenset(result)
