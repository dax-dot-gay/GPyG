# Message Management

*Operations related to encryption, decryption, and signing of messages.*

---

## Encrypting a Message

### Using Public-Key Encryption

GPyG can encrypt a message to any number of recipients as follows:

```python
# Encrypts the message in ASCII format to the two keys specified.
# Keys can either be Key objects or the Key IDs of keys.
# This method returns bytes, which may then be saved to a file or otherwise processed
encrypted = gpg.messages.encrypt(b"my secret message", first_key, second_key)
```

### Using Symmetric Encryption

If symmetric encryption is required, `encrypt_symmetric(...)` may be used as follows:

```python
# Encrypts the message symmetrically using the provided password. When no format is specified, defaults to outputting ascii-encoded data.
encrypted = gpg.messages.encrypt_symmetric(b"my secret message", "a-secret-password")
```

## Decrypting a Message

`decrypt(...)` can be used to decrypt both public-key and symmetric encrypted data as follows:

```python
# Decrypt using the recipient's private key
decrypted_pk = gpg.messages.decrypt(encrypted, key=recipient_key, passphrase="recipient-passphrase")

# Decrypt symmetric data using the encryption key
decrypted_symmetric = gpg.messages.decrypt(encrypted, passphrase="a-secret-password)
```

## Getting a Message's Recipients

Given an encrypted message, `get_recipients(...)` can retrieve a list of the message's recipients. Some examples of its usage follow:

```python
# Return all recipients associated with the data, whether the local GPG instance knows about them or not.
recipients = gpg.messages.get_recipients(data)

# Return only the known recipients as Key objects
recipients = gpg.messages.get_recipients(data, include=["known"])

# Return all fingerprints of recipients
recipients = gpg.messages.get_recipients(data, translate=False)
```

## Sign a Message

Messages can be signed, creating several types of generated signature. For example:

```python
# Generate a detached signature for a key
signature = gpg.messages.sign(message, signer_key, mode="detach", passphrase="my-passphrase")

# Generate an attached signature and return the entire signed message as PGP binary
signed_message = gpg.messages.sign(message, signer_key, mode="standard", passphrase="my-passphrase", format="pgp")
```

## Verify a Message

Given either a signed message or a message and its default signature, return a list of valid signers of that message.

```python
# Verify a message with a detached signature
signers = gpg.messages.verify(message, signature=detached_signature)

# Verify a signed message
signers = gpg.messages.verify(signed_message)
```