import pytest


@pytest.fixture
def expect_deprecation():
    with pytest.warns(DeprecationWarning):
        yield
