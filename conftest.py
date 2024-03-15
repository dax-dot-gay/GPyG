from pathlib import Path
import pytest, gpyg


@pytest.fixture
def context():
    with gpyg.GPG() as gpg:
        yield gpg


@pytest.fixture
def homed_context(homedir: str):
    with gpyg.GPG(homedir=homedir) as gpg:
        yield gpg


@pytest.fixture
def homedir(tmp_path_factory: pytest.TempPathFactory) -> str:
    return str(tmp_path_factory.mktemp("homedir").resolve())
