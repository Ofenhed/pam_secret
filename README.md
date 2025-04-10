This is to be used in `pam.d/system-auth` by creating a profile which uses password.

Previous:
```
auth        sufficient              pam_unix.so {if not "without-nullok":nullok}
```

After:
```
auth        [success=ok default=1 ignore=ignore]              pam_unix.so {if not "without-nullok":nullok}
auth        [success=done]                                    pam_tpm2.so pcr_register=23
```

Preferably you should also run `tpm2_pcrreset` on your register on screen saver activation.
