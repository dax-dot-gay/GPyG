# Key Operator

---

The Key Operator handles operations on GPG keys. It should not be instantiated directly, but instead gotten through `GPG(...).keys`

## `KeyOperator()` - Main Operator

Main class, handles operations on the entire keyring (fetching keys, generating keys, etc)

::: gpyg.operators.KeyOperator

---

## `Key()` - Key Wrapper

Wrapper for individual key functions, such as signing, encryption, etc. Returned by `KeyOperator()` methods.

::: gpyg.operators.Key