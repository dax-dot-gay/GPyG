# Common Operations

*The following examples assume you already have a GPG instance initialized, called `gpg`*
#### Getting GPG Configuration

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

#### Generating Keys

```python
...
new_key = gpg.keys.generate_key(
    "your-name", # Required
    email="your@email.com", # Optional
    comment="My Really Cool Key", # Optional
    algorithm="rsa2048", # Leaving this empty will select the default algorithm
    usage=["sign", "auth", "encr"], # Leaving this empty will set the default usage.
    expiration=None, # None for no expiration, but may also be a datetime/timedelta/int seconds
    passphrase="a-super-secure-password", # Leave as None for no passphrase
)

print(new_key.model_dump_json(indent=4)) # Return the JSONified representation of the key
```

Keys are stored as `Key` objects, which extend [KeyModel](../api/models/keys.md/#key-model) with contextualized operations. For specific info on `Key` methods, see [Key](../api/operators/keys.md#key-key-wrapper).

#### Listing Keys

```python
...
# List all public keys
keys = gpg.keys.list_keys()

# List all secret keys with "bob" somewhere in their UIDs
keys = gpg.keys.list_keys(pattern="bob", key_type="secret")

# Get a specific public key with its fingerprint
key = gpg.keys.get_key("fingerprint")
```

As above, these methods will all return `Key` objects, which can be further used to operate on individual keys.

