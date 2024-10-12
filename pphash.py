#!python3
# Copyright is waived. No warranty is provided. Unrestricted use and modification is permitted.

import sys
from hashlib import sha3_256

try:
    from argon2 import PasswordHasher, Type
except ImportError:
    sys.exit("Install argon2 with 'pip3 install argon2-cffi'")

PURPOSE = """
Create a unique password by hashing a passphrase with Argon2

pphash.py <phrase>

examples:
  pphash.py  myphrase
  pphash.py  "my memorable phrase"
"""

CONFIG = {
    # argon2 configuration; changing any of these will change the resulting password
    'argon_hash_len': 16,
    'argon_memory_cost': 4194304,
    'argon_time_cost': 8,
    'argon_parallelism': 4,

    # prefix the password with one each of upper-case, lower-case, digit and symbol to ensure password compliance
    'password_prefix': 'pP1#'
}

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(PURPOSE)
    passphrase = sys.argv[1].encode('latin1')

    # in order to produce a consistent output we need to use the same salt each time. The salt is derived
    # as a cryptographic hash of the pass phrase
    salt = sha3_256(passphrase).digest()

    # generate the argon2 hash
    hasher = PasswordHasher(memory_cost=CONFIG['argon_memory_cost'],
                            salt_len=len(salt),
                            hash_len=CONFIG['argon_hash_len'],
                            time_cost=CONFIG['argon_time_cost'],
                            parallelism=CONFIG['argon_parallelism'],
                            type=Type.ID)
    _, argon_type, version, parameters, salt_b64, hash_b64 = hasher.hash(passphrase, salt=salt).split('$')

    # replace the default base64 symbols in the hash with symbols more typically accepted in passwords
    safe_hash = hash_b64.replace('+', '!').replace('/', '$')

    # add a prefix to ensure the output is compliant with most password minimum requirements
    password = f'{CONFIG["password_prefix"]}{safe_hash}'
    print(password)
