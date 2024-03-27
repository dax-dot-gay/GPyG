# Key Management

*Operations related to managing your keys.*

---

All key operations are performed under either an instance of `KeyOperator` returned by `GPG.keys` for non-key-specific operations, or an instance of `Key` for operations specific to a single key.

## Key Generation

To generate a key on the host system, the `KeyOperator.generate_key(...)` method is used as follows:

```python
# Generates a key with the UID "My Name" and all other parameters as default. No passphrase is specified.
new_key = gpg.keys.generate_key("My Name")

# Generates a key with a full UID and a passphrase.
new_key = gpg.keys.generate_key("My Name", email="my@email.com", comment="My really cool key", passphrase="secure-password")

# Generates a key with a name-only UID and an expiration date
new_key = gpg.keys.generate_key("My Name", expiration=datetime.datetime(1, 2, 2026))

# Generates a key with a name and passphrase, even if a key with that UID already exists.
new_key = gpg.keys.generate_key("My Name", passphrase="secure-password", force=True)
```

For further information, see [`KeyOperator`](../api/operators/keys.md#key-operator).

## Retrieving Keys

Keys can either be retrieved individually by fingerprint, or in aggregate based on a provided pattern.

```python
# Get a list of all public keys
keys = gpg.keys.list_keys(key_type="public")

# Get a list of all private keys matching the string "Alice"
keys = gpg.keys.list_keys(pattern="Alice", key_type="secret")

# Get the public key of the key with fingerprint "fake-fpr"
# If the key doesn't exist, this will return None.
keys = gpg.keys.get_key("fake-fpr")
```

Along with `KeyOperator.generate_key(...)`, the above methods all return instances of [`Key`](../api/operators/keys.md#key---key-wrapper), which wraps [`KeyModel`](../api/models/keys.md#key-model).

## Importing Keys

Keys can be imported from files as follows:

```python
gpg.keys.import_key("file_1.asc", "file_2.asc", ...)
```

`import_key(...)` can import any number of keys from files, which can then be retrieved as shown in [Retrieving Keys](#retrieving-keys).

## Working With Keys

A full listing of all `Key` functions can be found [here](../api/operators/keys.md#key---key-wrapper), however some common operations are as follows:

#### Reloading Key Info

Allows for reloading the data of an existing `Key` object without recreating it.
```python
key.reload() # Updates internal state & returns the updated model for operation chaining.
```

#### Exporting Keys

Exports a key's data into `bytes` which may then be written to a file or otherwise processed.
```python
# Exports a key as ascii
as_ascii = key.export()

# Exports a private key as PGP binary
as_pgp = private_key.export(mode="gpg")
```

A number of other options can be passed to `export(...)`, and are summarized in the API documentation.

#### Verifying Passphrase

Allows the verification of a passphrase (or verifying if the key is protected at all).
```python
# Whether the key has a passphrase
is_protected = key.is_protected()

# Whether the given password is correct (if the key is unprotected, this will always return True)
is_valid = key.check_password("my-password")
```

#### Signing Other Keys

Allows signing other keys with the current key.
```python
# Signs `other_key` with `key`, assuming key's password is "my-password".
key.sign_key(other_key, password="my-password")
```

#### Accessing Subkeys

Subkeys are stored under `Key.subkeys`, and are wrapped with similar functionality to `Key`. This allows deletion and/or modification of individual subkeys, similar to how one would do so for the primary key.

#### Deleting Keys

Keys & subkeys can delete themselves with the `Key.delete()` method, as follows:

```python
key.delete() # Delete both the public and private key associated with `key`.

key.delete(delete_both=False) # Only delete the current key (ie, if the key is a public key, do NOT delete the secret key as well.)
```
