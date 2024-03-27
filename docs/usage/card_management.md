# Smart Card Management

*Managing attached PGP Smartcards & their data*

---

## Prerequisites

To be able to access smartcard functions, you must have:

- A functioning PGP smartcard
- A local GPG configuration capable of interfacing with it

## The Smartcard Context

As all smartcard functions rely on a stateful CLI menu in the backend, all smartcard operations must be performed within the `GPG.smart_card()` context, as follows:

```python
with gpg.smart_card() as card:
    ...
```

Given a correct system & card configuration, this should connect to the card and allow for further communication.

## Getting Card Information

Information about the connected card can be retrieved with `card.active` as follows:

```python
with gpg.smart_card() as card:
    print(card.active)
```

If no card is present, this property will resolve to `None`.

## Generating Keys

Keys can be generated on-card such that they never interact with the host system. An example configuration is as follows:

```python
with gpg.smart_card() as card:
    card.generate_key("My Name", expires="2y", backup=True, key_passphrase="backup-password", force=True)
```

This example generates a key with the UID "My Name" that will expire in 2 years. The default card pin and admin pin are used, and the generated key will replace any already existing on the card. Additionally, a backup key with the password "backup-password" will be created on the host system.

## Further Information

Further information on smartcard management can be found in the [API Reference](../api/operators/cards.md).