import pytest

pytest_plugins = ["test_utils.pkcs11_utils.fixtures"]


@pytest.fixture
def expect_deprecation():
    with pytest.warns(DeprecationWarning):
        yield
