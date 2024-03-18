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


@pytest.fixture(scope="module")
def session(tmp_path_factory: pytest.TempPathFactory):
    with gpyg.GPG(homedir=str(tmp_path_factory.mktemp("homedir").resolve())) as gpg:
        gpg.keys.generate_key(
            "test-name",
            email="test-email",
            key_type="RSA",
            key_length=3072,
            passphrase="test-psk",
        )
        gpg.keys.generate_key(
            "test-name2",
            email="test-email2",
            key_type="DSA",
            key_length=2048,
            passphrase="test-psk",
        )
        gpg.keys.generate_key(
            "test-name3",
            email="test-email3",
            key_type="RSA",
            key_length=2048,
            passphrase="test-psk",
        )
        yield gpg


@pytest.fixture
def homedir(tmp_path_factory: pytest.TempPathFactory) -> str:
    return str(tmp_path_factory.mktemp("homedir").resolve())
