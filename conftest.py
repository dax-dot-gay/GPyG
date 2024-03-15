from pathlib import Path
import pytest, gpyg


@pytest.fixture
def context() -> gpyg.GPGMEContext:
    return gpyg.GPGMEContext()


@pytest.fixture
def homedir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return str(tmp_path_factory.mktemp("homedir").resolve())
