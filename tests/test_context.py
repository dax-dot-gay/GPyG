from gpyg import GPG
from gpyg.gpgme import GpgmeKeylist, GpgmePinentry


def test_context_armor(context: GPG):
    assert context.armor == False
    context.armor = True
    assert context.armor == True


def test_context_homedir(context: GPG, homedir: str):
    assert context.homedir == None
    context.homedir = homedir
    assert context.homedir == homedir


def test_context_textmode(context: GPG):
    assert context.textmode == False
    context.textmode = True
    assert context.textmode == True


def test_context_offline(context: GPG):
    assert context.offline == False
    context.offline = True
    assert context.offline == True


def test_context_pinentry(context: GPG):
    assert context.pinentry_mode == GpgmePinentry.MODE_LOOPBACK
    context.pinentry_mode = GpgmePinentry.MODE_DEFAULT
    assert context.pinentry_mode == GpgmePinentry.MODE_DEFAULT


def test_context_include_certs(context: GPG):
    assert context.included_certs == None
    context.included_certs = -1
    assert context.included_certs == -1


def test_context_keylist(context: GPG):
    assert context.keylist == GpgmeKeylist.MODE_LOCAL
    context.keylist = GpgmeKeylist.MODE_LOCAL | GpgmeKeylist.MODE_EXTERN
    assert context.keylist == GpgmeKeylist.MODE_LOCAL | GpgmeKeylist.MODE_EXTERN
