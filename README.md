# GPyG
A modern pythonic wrapper around GPG

### Installation

**Requirements:**

- At least Python 3.12
- A working GNUPG installation

GPyG can be installed from [PyPI](https://pypi.org/project/gpyg/) with the following command:

```bash
python -m pip install gpyg
```

### Basic Usage

```python
from gpyg import GPG

with GPG() as gpg:
    print(gpg.keys.list_keys())
    print(gpg.keys.list_keys()[0].export())
```

### Documentation

In-depth documentation and the API reference is hosted at [https://itecai.github.io/GPyG](https://itecai.github.io/GPyG)

