import pytest, gpyg


@pytest.fixture
def context() -> gpyg.GPGMEContext:
    return gpyg.GPGMEContext()
