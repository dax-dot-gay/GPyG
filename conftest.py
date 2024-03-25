import pytest
from gpyg import GPG, CardOperator


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
            passphrase=f"test-psk-{user}" if user < 2 else None,
        )

    return scoped_instance


@pytest.fixture(scope="module")
def smallenv(scoped_instance: GPG):
    key = scoped_instance.keys.generate_key(
        "user", email="user@example.com", passphrase="user"
    )
    return scoped_instance, key


@pytest.fixture
def interactive(instance: GPG):
    signee = instance.keys.generate_key(
        name="Signee", email="signee@example.com", passphrase="signee"
    )
    signer = instance.keys.generate_key(
        name="Signer", email="signer@example.com", passphrase="signer"
    )
    with signee.edit(user=signer.fingerprint) as editor:
        yield editor, signee, signer
