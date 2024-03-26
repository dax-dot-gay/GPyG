# GPyG Documentation
*Pure Python GPG CLI Wrapper*

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

### Features

- Stateless key management
- Direct interaction with `gpg --edit-key`
- Message manipulation
- Smartcard operations with `gpg --edit-card`

### Security

In its current state, I wouldn't immediately reccomend using this library in production. However, I have implemented the following security measures to prevent shell injection and privilege escalation to the best of my ability:

- All inputs to the shell are escaped (using Python's `shlex`)
- All commands are run through Python's `subprocess` module, with `shell=False`.
- Passwords are passed on STDIN, preventing other users from viewing any passwords passed to GPG.



