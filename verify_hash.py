#!/usr/bin/env python
import argparse
import hmac
import hashlib
import subprocess

HASH_TYPE_STORAGE_ENCRYPTION_KEY = b"Storage Encryption Key"
HASH_TYPE_HMAC_REQUEST = b"Hashed Authenticated Messages Head"
HASH_TYPE_AUTHENTICATED_HMAC_REQUEST = b"Hashed Messages Head"
HASH_TYPE_MAP_AUTH_TOKEN = b"Hashed Messages End"
HASH_TYPE_USER_PASSWORD = b"User Authentication Token"

def sha_hmac_fn(print_debug):
    def sha_hmac(secret, msg):
        result = hmac.digest(secret, msg, hashlib.sha256)
        if print_debug:
            print(f"HMAC(\"{secret}\", \"{msg}\") = \"{result}\"")
        return result
    return sha_hmac


if __name__ == "__main__":
  opts = argparse.ArgumentParser()
  subparsers = opts.add_subparsers(dest="action")
  password = subparsers.add_parser('decrypt', description="Decrypt the protected-user-cred file")
  opts.add_argument("--system-secret-file", required=True, type=str)
  password.add_argument("--user-cred-file", required=True, type=str)
  password.add_argument("--password", required=True, type=str)
  hasher = subparsers.add_parser('pam', description="Calculate PAM translated password")
  hasher.add_argument("--password", required=True, type=str)
  hasher = subparsers.add_parser('hmac', description="Generate persistent random value")
  hasher.add_argument("--authenticated-hash", action='store_true')
  hasher.add_argument("hmac_text", nargs='+')
  opts.add_argument("--decrypted-cred-file", required=True, type=str)
  opts.add_argument("--print-hmac", action='store_true')
  args = opts.parse_args()
  sha_hmac = sha_hmac_fn(args.print_hmac)
  system_secret = None
  with open(args.system_secret_file, "rb") as f:
    system_secret = f.read()

  if args.action == "decrypt":
    user_cred = None
    password = bytes(args.password, "utf-8")
    # Password hash
    decrypt_password = sha_hmac(sha_hmac(HASH_TYPE_STORAGE_ENCRYPTION_KEY, password), system_secret)
    print(f"Password: {decrypt_password}")
    child = subprocess.Popen(["scrypt", "dec", "--passphrase", "dev:stdin-once", args.user_cred_file, args.decrypted_cred_file], stdin=subprocess.PIPE)
    while len(decrypt_password) > 0:
      c = child.stdin.write(decrypt_password)
      decrypt_password = decrypt_password[c:]
    child.stdin.close()
    child.wait()
  else:
    with open(args.decrypted_cred_file, "rb") as f:
        decrypted_cred = f.read()

    if args.action == "hmac":
      tokens = map(lambda x: bytes(x, "utf-8"), args.hmac_text)
      tokens = list(tokens)
      # Hash return data definition
      hash_type = HASH_TYPE_AUTHENTICATED_HMAC_REQUEST if args.authenticated_hash else HASH_TYPE_HMAC_REQUEST
      hash = sha_hmac(hash_type, decrypted_cred)
      hash = sha_hmac(hash, system_secret)
      for t in tokens:
          hash = sha_hmac(hash, t)
      hash = sha_hmac(hash, decrypted_cred)
      hex_hash = map(lambda x: ('0' + hex(x)[2:])[-2:], hash)
      print(''.join(hex_hash))

    elif args.action == "pam":
      hash = sha_hmac(HASH_TYPE_USER_PASSWORD, bytes(args.password, "utf-8"))
      hash = sha_hmac(hash, decrypted_cred)
      hash = sha_hmac(hash, system_secret)
      hex_hash = map(lambda x: ('0' + hex(x)[2:])[-2:], hash)
      print(''.join(hex_hash))
