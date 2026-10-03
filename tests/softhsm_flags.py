"""Child process: print the token flags of the SoftHSM token with a given label (HOME selects the SoftHSM config).
usage: softhsm_flags.py MODULE LABEL  ->  one integer (CK_FLAGS)"""

import sys

import pkcs11

lib = pkcs11.lib(sys.argv[1])
print(next(t for t in (s.get_token() for s in lib.get_slots(token_present=True)) if t.label == sys.argv[2]).flags.value)
