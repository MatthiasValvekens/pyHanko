"""
Unit tests for the policy graph algorithm from RFC 9618.

The examples from that document are reproduced here as far as possible;
figure references in the test names refer to the figures in the RFC.
"""

import pytest
from asn1crypto import x509
from pyhanko_certvalidator.path import QualifiedPolicy
from pyhanko_certvalidator.policy_graph import (
    ANY_POLICY,
    PolicyGraph,
    apply_policy_mapping,
    authority_constrained_policies,
    update_policy_graph,
    user_constrained_policies,
)

GOLD = '2.999.1'
SILVER = '2.999.2'
WHITE = '2.999.3'
YELLOW = '2.999.4'
RED = '2.999.5'
BLUE = '2.999.6'


def cps(url: str) -> x509.PolicyQualifierInfo:
    return x509.PolicyQualifierInfo(
        {
            'policy_qualifier_id': 'certification_practice_statement',
            'qualifier': x509.IA5String(url),
        }
    )


def policy(oid: str, *qualifiers) -> x509.PolicyInformation:
    values = {'policy_identifier': oid}
    if qualifiers:
        values['policy_qualifiers'] = x509.PolicyQualifierInfos(
            list(qualifiers)
        )
    return x509.PolicyInformation(values)


def mappings(*pairs) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for issuer_domain_policy, subject_domain_policy in pairs:
        result.setdefault(issuer_domain_policy, set()).add(
            subject_domain_policy
        )
    return result


def describe(graph: PolicyGraph | None) -> list[dict]:
    """
    Render a graph as a list of levels, each mapping a policy OID to its
    expected policy set and the OIDs of its parents.
    """
    if graph is None:
        return []
    return [
        {
            node.valid_policy: (
                node.expected_policy_set,
                sorted(parent.valid_policy for parent in node.parents),
            )
            for node in graph.nodes_at_depth(depth)
        }
        for depth in range(graph.depth + 1)
    ]


def node_count(graph: PolicyGraph) -> int:
    return sum(
        len(list(graph.nodes_at_depth(depth)))
        for depth in range(graph.depth + 1)
    )


def qualifiers_of(node) -> set[bytes]:
    return {qualifier.dump() for qualifier in node.qualifier_set}


def process(graph, depth, *policies, any_policy_uninhibited=True):
    return update_policy_graph(
        list(policies),
        graph,
        depth=depth,
        any_policy_uninhibited=any_policy_uninhibited,
    )


def test_initial_graph():
    graph = PolicyGraph()
    assert describe(graph) == [{ANY_POLICY: ({ANY_POLICY}, [])}]
    assert graph.depth == 0


def test_figure4_exact_match_shares_a_single_node():
    # a graph with Red expecting {Gold, White} and Blue expecting
    # {Gold, Yellow} at depth 1...
    graph = PolicyGraph()
    process(graph, 1, policy(RED), policy(BLUE))
    graph.node_at(1, RED).expected_policy_set = {GOLD, WHITE}
    graph.node_at(1, BLUE).expected_policy_set = {GOLD, YELLOW}

    # ...processing a certificate asserting Gold and Silver yields a single
    # Gold node with two parents; Silver is not matched
    result = process(graph, 2, policy(GOLD), policy(SILVER))

    assert describe(result)[2] == {GOLD: ({GOLD}, [RED, BLUE])}


def test_figure5_unmatched_policies_under_any_policy():
    graph = PolicyGraph()
    q_silver = cps('http://silver.example.com')

    result = process(graph, 1, policy(GOLD), policy(SILVER, q_silver))

    assert describe(result)[1] == {
        GOLD: ({GOLD}, [ANY_POLICY]),
        SILVER: ({SILVER}, [ANY_POLICY]),
    }
    assert qualifiers_of(result.node_at(1, GOLD)) == set()
    assert qualifiers_of(result.node_at(1, SILVER)) == {q_silver.dump()}


def test_figure6_any_policy_in_certificate():
    graph = PolicyGraph()
    process(graph, 1, policy(RED), policy(BLUE))
    graph.node_at(1, RED).expected_policy_set = {GOLD, SILVER}
    graph.node_at(1, BLUE).expected_policy_set = {GOLD}

    ap_q = cps('http://any.example.com')
    result = process(graph, 2, policy(ANY_POLICY, ap_q))

    assert describe(result)[2] == {
        GOLD: ({GOLD}, [RED, BLUE]),
        SILVER: ({SILVER}, [RED]),
    }
    assert qualifiers_of(result.node_at(2, GOLD)) == {ap_q.dump()}


def test_any_policy_inhibited():
    graph = PolicyGraph()
    process(graph, 1, policy(GOLD))

    result = process(graph, 2, policy(ANY_POLICY), any_policy_uninhibited=False)

    # nothing matched Gold's expected policy set, so the graph collapses
    assert result is None


def test_figure7_pruning_cascades():
    graph = PolicyGraph()
    process(graph, 1, policy(RED), policy(BLUE))
    graph.node_at(1, RED).expected_policy_set = {GOLD}
    graph.node_at(1, BLUE).expected_policy_set = {SILVER}
    process(graph, 2, policy(GOLD), policy(SILVER))
    graph.node_at(2, GOLD).expected_policy_set = {WHITE}
    graph.node_at(2, SILVER).expected_policy_set = {YELLOW}

    # only White survives at depth 3, so Silver loses its only child, and
    # Blue in turn loses its only child
    result = process(graph, 3, policy(WHITE))

    assert describe(result) == [
        {ANY_POLICY: ({ANY_POLICY}, [])},
        {RED: ({GOLD}, [ANY_POLICY])},
        {GOLD: ({WHITE}, [RED])},
        {WHITE: ({WHITE}, [GOLD])},
    ]


def test_pruning_to_null_graph():
    graph = PolicyGraph()
    process(graph, 1, policy(GOLD))

    assert process(graph, 2, policy(SILVER)) is None


def test_duplicate_policy_oid_is_ignored():
    graph = PolicyGraph()
    q = cps('http://first.example.com')

    result = process(
        graph, 1, policy(GOLD, q), policy(GOLD, cps('http://second.example'))
    )

    assert describe(result)[1] == {GOLD: ({GOLD}, [ANY_POLICY])}
    assert qualifiers_of(result.node_at(1, GOLD)) == {q.dump()}


def test_no_any_policy_parent_to_fall_back_on():
    graph = PolicyGraph()
    process(graph, 1, policy(GOLD), policy(SILVER))

    # no anyPolicy node at depth 1, and White isn't expected by anything
    result = process(graph, 2, policy(GOLD), policy(WHITE))

    assert describe(result)[2] == {GOLD: ({GOLD}, [GOLD])}


def test_no_exponential_blowup():
    # the attack chain from RFC 9618 § 3.2: every certificate asserts two
    # policies and maps each of them to both
    depth_target = 25
    graph = PolicyGraph()
    for depth in range(1, depth_target + 1):
        result = process(graph, depth, policy(GOLD), policy(SILVER))
        assert result is not None
        graph = result
        apply_policy_mapping(
            mappings(
                (GOLD, GOLD),
                (GOLD, SILVER),
                (SILVER, GOLD),
                (SILVER, SILVER),
            ),
            graph,
            depth=depth,
            policy_mapping_uninhibited=True,
        )

    # a policy tree would have 2 ** 25 nodes at the deepest level alone
    assert node_count(graph) == 2 * depth_target + 1


class TestPolicyMapping:
    def test_mapped_node_expects_subject_domain_policies(self):
        graph = PolicyGraph()
        process(graph, 1, policy(GOLD))

        result = apply_policy_mapping(
            mappings((GOLD, WHITE), (GOLD, YELLOW)),
            graph,
            depth=1,
            policy_mapping_uninhibited=True,
        )

        assert describe(result)[1] == {GOLD: ({WHITE, YELLOW}, [ANY_POLICY])}

    def test_mapping_under_any_policy(self):
        ap_q = cps('http://any.example.com')
        graph = PolicyGraph()
        process(graph, 1, policy(ANY_POLICY, ap_q))

        result = apply_policy_mapping(
            mappings((GOLD, WHITE)),
            graph,
            depth=1,
            policy_mapping_uninhibited=True,
        )

        assert describe(result)[1] == {
            ANY_POLICY: ({ANY_POLICY}, [ANY_POLICY]),
            GOLD: ({WHITE}, [ANY_POLICY]),
        }
        assert qualifiers_of(result.node_at(1, GOLD)) == {ap_q.dump()}

    def test_no_mapping_without_any_policy(self):
        graph = PolicyGraph()
        process(graph, 1, policy(SILVER))

        result = apply_policy_mapping(
            mappings((GOLD, WHITE)),
            graph,
            depth=1,
            policy_mapping_uninhibited=True,
        )

        assert describe(result)[1] == {SILVER: ({SILVER}, [ANY_POLICY])}

    def test_inhibited_mapping_deletes_node(self):
        graph = PolicyGraph()
        process(graph, 1, policy(GOLD), policy(SILVER))

        result = apply_policy_mapping(
            mappings((GOLD, WHITE)),
            graph,
            depth=1,
            policy_mapping_uninhibited=False,
        )

        assert describe(result)[1] == {SILVER: ({SILVER}, [ANY_POLICY])}

    def test_inhibited_mapping_of_absent_policy(self):
        graph = PolicyGraph()
        process(graph, 1, policy(SILVER))

        result = apply_policy_mapping(
            mappings((GOLD, WHITE)),
            graph,
            depth=1,
            policy_mapping_uninhibited=False,
        )

        assert describe(result)[1] == {SILVER: ({SILVER}, [ANY_POLICY])}

    def test_inhibited_mapping_can_null_out_the_graph(self):
        graph = PolicyGraph()
        process(graph, 1, policy(GOLD), policy(SILVER))

        # the second deletion empties the graph; the third mapping must not
        # trip over the resulting NULL graph
        result = apply_policy_mapping(
            mappings((GOLD, WHITE), (SILVER, YELLOW), (RED, BLUE)),
            graph,
            depth=1,
            policy_mapping_uninhibited=False,
        )

        assert result is None


class TestGraphOperations:
    def test_nodes_outside_the_graph(self):
        graph = PolicyGraph()
        assert list(graph.nodes_at_depth(-1)) == []
        assert list(graph.nodes_at_depth(1)) == []
        assert graph.node_at(1, ANY_POLICY) is None
        assert graph.node_at(-1, ANY_POLICY) is None

    def test_duplicate_node_rejected(self):
        graph = PolicyGraph()
        with pytest.raises(ValueError, match='already occurs'):
            graph.add_node(0, ANY_POLICY, (), {ANY_POLICY}, ())

    def test_delete_unknown_node_is_a_noop(self):
        graph = PolicyGraph()
        root = graph.node_at(0, ANY_POLICY)
        graph.delete_node(root)
        graph.delete_node(root)
        assert describe(graph) == [{}]

    def test_delete_node_takes_orphans_with_it(self):
        graph = PolicyGraph()
        process(graph, 1, policy(GOLD), policy(SILVER))
        graph.node_at(1, GOLD).expected_policy_set = {WHITE}
        graph.node_at(1, SILVER).expected_policy_set = {WHITE, YELLOW}
        process(graph, 2, policy(WHITE), policy(YELLOW))

        graph.delete_node(graph.node_at(1, SILVER))

        # Yellow only hung off Silver, so it goes as well; White survives
        # through Gold
        assert describe(graph) == [
            {ANY_POLICY: ({ANY_POLICY}, [])},
            {GOLD: ({WHITE}, [ANY_POLICY])},
            {WHITE: ({WHITE}, [GOLD])},
        ]

    def test_ancestors_and_descendants_of_a_diamond(self):
        graph = PolicyGraph()
        process(graph, 1, policy(GOLD), policy(SILVER))
        graph.node_at(1, GOLD).expected_policy_set = {WHITE}
        graph.node_at(1, SILVER).expected_policy_set = {WHITE}
        process(graph, 2, policy(WHITE))
        graph.node_at(2, WHITE).expected_policy_set = {YELLOW}
        process(graph, 3, policy(YELLOW))

        white = graph.node_at(2, WHITE)
        assert sorted(node.valid_policy for node in white.ancestors()) == [
            GOLD,
            SILVER,
            ANY_POLICY,
        ]
        root = graph.node_at(0, ANY_POLICY)
        assert sorted(node.valid_policy for node in root.descendants()) == [
            GOLD,
            SILVER,
            WHITE,
            YELLOW,
        ]


class TestUserConstrainedPolicies:
    def test_null_graph(self):
        assert (
            user_constrained_policies(None, 3, frozenset([GOLD])) == frozenset()
        )
        assert authority_constrained_policies(None, 3) == {}

    def test_zero_length_path(self):
        graph = PolicyGraph()

        result = user_constrained_policies(graph, 0, frozenset([ANY_POLICY]))

        assert result == frozenset(
            [
                QualifiedPolicy(
                    user_domain_policy_id=ANY_POLICY,
                    issuer_domain_policy_id=ANY_POLICY,
                    qualifiers=frozenset(),
                )
            ]
        )

    def test_qualifiers_are_gathered_across_the_path(self):
        q_gold = cps('http://gold.example.com')
        q_white = cps('http://white.example.com')
        graph = PolicyGraph()
        process(graph, 1, policy(GOLD, q_gold))
        apply_policy_mapping(
            mappings((GOLD, WHITE)),
            graph,
            depth=1,
            policy_mapping_uninhibited=True,
        )
        process(graph, 2, policy(WHITE, q_white))

        (result,) = user_constrained_policies(graph, 2, frozenset([ANY_POLICY]))

        assert result.user_domain_policy_id == GOLD
        assert result.issuer_domain_policy_id == WHITE
        assert {qualifier.dump() for qualifier in result.qualifiers} == {
            q_gold.dump(),
            q_white.dump(),
        }

    def test_identical_qualifiers_are_deduplicated(self):
        graph = PolicyGraph()
        process(graph, 1, policy(GOLD, cps('http://gold.example.com')))
        process(graph, 2, policy(GOLD, cps('http://gold.example.com')))

        (result,) = user_constrained_policies(graph, 2, frozenset([ANY_POLICY]))

        assert len(result.qualifiers) == 1

    def test_only_policies_in_the_root_domain_are_reported(self):
        graph = PolicyGraph()
        process(graph, 1, policy(GOLD))
        apply_policy_mapping(
            mappings((GOLD, WHITE), (GOLD, YELLOW)),
            graph,
            depth=1,
            policy_mapping_uninhibited=True,
        )
        process(graph, 2, policy(WHITE), policy(YELLOW))

        authority_constrained = authority_constrained_policies(graph, 2)

        assert set(authority_constrained) == {GOLD}
        assert authority_constrained[GOLD].issuer_domain_policy_oids == (
            frozenset([WHITE, YELLOW])
        )

    def test_unacceptable_policies_are_filtered_out(self):
        graph = PolicyGraph()
        process(graph, 1, policy(GOLD), policy(SILVER))
        process(graph, 2, policy(GOLD), policy(SILVER))

        result = user_constrained_policies(graph, 2, frozenset([GOLD]))

        assert {qp.user_domain_policy_id for qp in result} == {GOLD}

    def test_no_acceptable_policies(self):
        graph = PolicyGraph()
        process(graph, 1, policy(GOLD))
        process(graph, 2, policy(GOLD))

        assert (
            user_constrained_policies(graph, 2, frozenset([SILVER]))
            == frozenset()
        )

    def test_trailing_any_policy_expands_to_user_initial_policy_set(self):
        ap_q = cps('http://any.example.com')
        graph = PolicyGraph()
        process(graph, 1, policy(ANY_POLICY, ap_q), policy(GOLD))
        process(graph, 2, policy(ANY_POLICY, ap_q), policy(GOLD))

        result = user_constrained_policies(graph, 2, frozenset([GOLD, SILVER]))

        assert {
            (qp.user_domain_policy_id, qp.issuer_domain_policy_id)
            for qp in result
        } == {(GOLD, GOLD), (SILVER, SILVER)}
        by_policy = {qp.user_domain_policy_id: qp for qp in result}
        assert by_policy[GOLD].qualifiers == frozenset()
        assert {
            qualifier.dump() for qualifier in by_policy[SILVER].qualifiers
        } == {ap_q.dump()}
