This is to be used in `pam.d/system-auth` by creating a profile which uses password.

> [!WARNING]
> This is still in early Proof of Concept stage. Any usage is at your own risk.

Previous:
```
auth    sufficient    pam_unix.so {if not "without-nullok":nullok}
```

After:
```
auth    [success=ok new_authtok_reqd=ok default=1 ignore=ignore]    pam_unix.so {if not "without-nullok":nullok}
auth    [default=done ]                                             pam_secret.so
```

Preferably you should also run `tpm2_pcrreset` on your register on screen saver activation.

