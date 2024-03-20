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


@pytest.fixture(scope="module")
def environment(scoped_instance: GPG) -> GPG:
    for user in range(4):
        scoped_instance.keys.generate_key(
            name=f"Test User {user}",
            email=f"test-user-{user}@example.com",
            comment=f"Test user # {user}",
            passphrase=f"test-psk-{user}",
        )

    return scoped_instance
