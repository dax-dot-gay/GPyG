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

---

## `KeyEditor()` - Wrapper for `gpg --edit-key`

Wraps advanced key editing functions in a stateless interface. Returned by `Key().edit(...)`. Operations in this category should be considered unsafe, as they rely on an unstable terminal menu to function.

::: gpyg.operators.KeyEditor