# Scratchpad for quick tests

import gpyg
from gpyg.gpgme import GpgmeKeylist

print(repr(GpgmeKeylist.MODE_EPHEMERAL | GpgmeKeylist.MODE_LOCAL))
