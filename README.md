> [!WARNING]
> This is still in early Proof of Concept stage. Any usage is at your own risk.

This program creates a persistent random seed based on protected files and the
user's password. It can be called as `pam_secret s=qvm s=personal s=mail` and
will return a cryptographically secure random hex encoded string, which is
persistent based on the system secret, user `persistent key` and user password.
Everything on the command line of `pam_secret` will be executed in the same
session. Note that the hash requires the `session secret` to be decrypted, but
the hash will depend on whether the user is authenticated in the current
session. This means that `pam_secret s=some_key` will return a different value
from `pam_secret auth s=some_key`. This difference is based on hard coded
values, changing your password does not invalidate any persistence.

This program acts as a PAM module that forks to a daemon. The daemon has access
to a system secret and the user's encrypted state. The encrypted state is
encrypted (for now hard coded) as taking ~8 seconds to decrypt (the `persistent
key`). Once encrypted it creates an two in memory only copies of the secret.
One is encrypted in such a way that decryption takes about 2 seconds (the
`protected key`), one is stored in plain text (the `session key`). This means
that authenticating against the `persistent key` will take 8 seconds if it
succeeds and 10 seconds if it fails.

While the `session key` is stored in memory, the daemon responds to hashing
requests. The `session key` can be cleared by executing `pam_secret lock`. In
this state, the PAM module will decrypt the `protected key` instead of the
`persistent key`, meaning that authentication takes 2 seconds instead.

> [!WARNING]
> Hibernation is blocked while `pam_secret` is running.

The saved state is intended to be removed if the computer is unattended. To
remove the plain text secret you can run `pam_secret lock`. This still leaves
the `protected key` in memory, so unlock attempts from the screen lock will
take 2 seconds. When the user logs out, or if you intend to hibernate the
computer, you can shut the daemon down by removing the socket from
`/run/user/$UID/encrypted-shadow`.

While this module can authenticate the use, that is not how it is intended to
be used. Using this module to authenticate the user means that the user
password might still be stored in such a way that it is still crackable by
brute force by the shadow entry instead of the encrypted state. The way this
module is intended to mitigate that issue is the `translate_authtok` parameter
in the PAM configuration. It creates a persistent random key which is dependent
of the secret state. This means that the user is still authenticated by another
PAM module, for example `pam_unix.so` or a domain controller.

To see how the random values are generated, see
[verify\_hash.py](verify_hash.py).

## Install
This is to be used in `pam.d/system-auth`. It will work as an `auth` and
`password` PAM module. The `password` module means that if you are in the group
that is allowed to use `pam_secret`, then you will be able to create a system
secret simply by executing `passwd` (if `auto_install` is in the argument
list).

The `auth` module will ignore users who aren't members of the authorized group,
and users who doesn't yet have a `persistent key`.

The module is intended to be added right before the primary `auth` module. Most
likely that's `pam_unix.so`. The `auth` module should be marked as `optional`,
meaning that it will read your password and unlock your secret (if it exists).

The `password` module should be marked as a requisite module right before your
primary `password` module. If you mark the `password` `pam_secret.so` as
`sufficient`, then your previous password will still be saved by the next
module (such as `pam_unix.so`). If you mark it as `required` instead of
`requisite`, then there might be cases where you change your password for the
next module without changing the password of the `pam_secret.so` key.

After:
```
auth    optional    pam_secret.so translate_authtok
auth    sufficient    pam_unix.so {if not "without-nullok":nullok}

password   requisite    pam_secret.so auto_install translate_authtok
password   sufficient    pam_unix.so yescrypt shadow nullok use_authtok
```

