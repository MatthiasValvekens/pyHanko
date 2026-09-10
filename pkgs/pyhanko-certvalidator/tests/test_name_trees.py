import pytest
from pyhanko_certvalidator.name_trees import (
    NameConstraintError,
    dns_tree_contains,
    email_tree_contains,
    host_tree_contains,
    uri_tree_contains,
)


@pytest.mark.parametrize(
    'base,other,expected',
    [
        ('example.com', 'example.com', True),
        ('example.com', 'www.example.com', True),
        ('example.com', 'notexample.com', False),
        ('example.com', 'example.org', False),
        ('www.example.com', 'example.com', False),
        # case folding (RFC 4343)
        ('example.com', 'EXAMPLE.COM', True),
        ('EXAMPLE.COM', 'example.com', True),
        ('example.com', 'WWW.Example.CoM', True),
        ('ExAmPlE.com', 'sub.example.COM', True),
        ('example.com', 'EXAMPLE.ORG', False),
        # trailing (root) dot is not significant
        ('example.com', 'example.com.', True),
        ('example.com.', 'example.com', True),
        ('example.com.', 'example.com.', True),
        ('example.com', 'WWW.EXAMPLE.COM.', True),
        # only ASCII case is folded; RFC 4343 s 3 gives 0xDD/0xFD as a
        # pair that must not match, though str.lower() would fold it
        ('ýexample.com', 'Ýexample.com', False),
    ],
)
def test_dns_tree_contains(base, other, expected):
    assert dns_tree_contains(base, other) is expected


@pytest.mark.parametrize(
    'base,other,expected',
    [
        ('example.com', 'example.com', True),
        ('example.com', 'www.example.com', False),
        ('.example.com', 'www.example.com', True),
        ('.example.com', 'example.com', False),
        ('.example.com', 'a.b.example.com', True),
        # case folding
        ('example.com', 'EXAMPLE.COM', True),
        ('EXAMPLE.com', 'example.COM', True),
        ('.example.com', 'WWW.Example.Com', True),
        ('.EXAMPLE.COM', 'www.example.com', True),
        ('example.com', 'example.org', False),
        # trailing (root) dot is not significant
        ('example.com', 'example.com.', True),
        ('example.com.', 'example.com', True),
        ('.example.com', 'WWW.EXAMPLE.COM.', True),
        ('.example.com.', 'www.example.com', True),
    ],
)
def test_host_tree_contains(base, other, expected):
    assert host_tree_contains(base, other) is expected


def test_host_tree_contains_rejects_empty_base():
    with pytest.raises(NameConstraintError, match='with an empty'):
        host_tree_contains('', 'example.com')


@pytest.mark.parametrize(
    'base,other,expected',
    [
        ('user@example.com', 'user@example.com', True),
        ('user@example.com', 'other@example.com', False),
        ('user@example.com', 'example.com', False),
        ('example.com', 'user@example.com', True),
        ('.example.com', 'user@www.example.com', True),
        ('.example.com', 'user@example.com', False),
        # the host part folds case, the local part does not
        ('user@example.com', 'user@EXAMPLE.COM', True),
        ('user@EXAMPLE.COM', 'user@example.com', True),
        ('user@example.com', 'USER@example.com', False),
        ('example.com', 'user@EXAMPLE.COM', True),
        ('EXAMPLE.COM', 'user@example.com', True),
        ('.example.com', 'user@WWW.EXAMPLE.COM', True),
        # trailing (root) dot is not significant
        ('user@example.com', 'user@example.com.', True),
        ('user@example.com.', 'user@example.com', True),
        ('example.com', 'user@example.com.', True),
    ],
)
def test_email_tree_contains(base, other, expected):
    assert email_tree_contains(base, other) is expected


@pytest.mark.parametrize(
    'base,other,expected',
    [
        ('example.com', 'http://example.com/foo', True),
        ('example.com', 'http://www.example.com/foo', False),
        ('.example.com', 'http://www.example.com/foo', True),
        # case folding and trailing dot, inherited from host_tree_contains
        ('example.com', 'http://EXAMPLE.COM/foo', True),
        ('.example.com', 'https://WWW.Example.Com:8443/foo', True),
        ('example.com', 'http://example.com./foo', True),
        ('example.com', 'http://example.org/foo', False),
    ],
)
def test_uri_tree_contains(base, other, expected):
    assert uri_tree_contains(base, other) is expected


@pytest.mark.parametrize('uri', ['http://192.0.2.1/foo', 'not a uri'])
def test_uri_tree_contains_requires_fqdn(uri):
    with pytest.raises(NameConstraintError, match='require URIs'):
        uri_tree_contains('example.com', uri)
