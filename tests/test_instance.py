from gpyg import *


def test_instance_creation(homedir):
    instance = GPG(homedir=homedir, kill_existing_agent=True)
    assert instance.session
    assert instance._config == None
    assert instance.config == instance._config


def test_instance_config(homedir):
    instance = GPG(homedir=homedir, kill_existing_agent=True)
    assert instance.config.version
    assert len(instance.config.compression_algorithms) > 0
    assert len(instance.config.digest_algorithms) > 0
    assert len(instance.config.symmetric_algorithms) > 0
    assert len(instance.config.public_key_algorithms) > 0
    assert len(instance.config.ecc_curves) > 0
    assert instance.keys
