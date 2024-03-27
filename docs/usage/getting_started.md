# Getting Started

*How to use the basic GPyG Features*

---

## Initializing a GPG Instance

All GPyG operations are methods of a [`GPG`](../api/gpg-instance.md) or its children. This instance can be initialized as follows:

```python
from gpyg import GPG

gpg = GPG(homedir="...", kill_existing_agent=True)
```

The `homedir` argument specifies the homedir to use for this GPG instance. If left empty, it will default to the system's default GPG homedir, which if modified unintentionally may have negative consequences for the system's GPG configuration. Thus, it is *generally* a good idea to set this directory to a path specific to GPyG, or a temporary directory if persistence isn't required.

In the general case of using a non-standard homedir, `kill_existing_agent` should be set to `True`. In testing, the behavior of `gpg-agent` when the GPG homedir changes is erratic, which may cause other operations to fail unexpectedly. Additionally, due to GPG being inherently stateful, use of the GPG CLI directly while GPyG operations are running may cause either process to fail or act unexpectedly.

## Getting GPG Configuration

`GPG.config` provides an object containing information about the configuration of the underlying GPG installation (see [`GPGConfig`](../api/models/other.md#gpgconfig)). Assuming a `GPG` instance already exists, it can be invoked as follows:

```python
...
config = gpg.config

# Get GPG version
print(config.version)

# Get supported PK algorithms, as a {name: id} mapping
print(config.public_key_algorithms)

# Get supported symmetric algorithms, as a {name: id} mapping
print(config.symmetric_algorithms)

# Get supported digest algorithms, as a {name: id} mapping
print(config.digest_algorithms)

# Get supported compression algorithms, as a {name: id} mapping
print(config.compression_algorithms)

# Get list of supported ECC curves
print(config.ecc_curves)
```

After the first call, the value of `config` is cached to allow for quicker access.