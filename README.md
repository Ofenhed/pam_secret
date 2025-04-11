This is to be used in `pam.d/system-auth` by creating a profile which uses password.

> [!WARNING]
> This risks leaking the password if it's feasible to sniff the TPM
> communication. The password will be hashed with `hash = HMAC(password,
> username)`, and optionally more times with `hmac_msg`, which will calculate a
> new HMAC with the previous hash as the secret and the `hmac_msg` as the
> message.

Previous:
```
auth    sufficient    pam_unix.so {if not "without-nullok":nullok}
```

After:
```
auth    [success=ok new_authtok_reqd=ok default=1 ignore=ignore]    pam_unix.so {if not "without-nullok":nullok}
auth    [default=done ]                                             pam_tpm2.so pcr_23=username [hmac_msg=TPM PCR Hash]
```

Preferably you should also run `tpm2_pcrreset` on your register on screen saver activation.

