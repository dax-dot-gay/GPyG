import pytest
from gpyg import GPG


@pytest.fixture(scope="module")
def scoped_homedir(tmp_path_factory: pytest.TempPathFactory) -> str:
    return str(tmp_path_factory.mktemp("gpg-homedir").absolute())


@pytest.fixture
def homedir(tmp_path_factory: pytest.TempPathFactory) -> str:
    return str(tmp_path_factory.mktemp("gpg-homedir").absolute())


@pytest.fixture(scope="module")
def scoped_instance(scoped_homedir) -> GPG:
    return GPG(homedir=scoped_homedir, kill_existing_agent=True)


@pytest.fixture
def instance(homedir) -> GPG:
    return GPG(homedir=homedir, kill_existing_agent=True)
