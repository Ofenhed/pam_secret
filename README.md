This is to be used in `pam.d/system-auth` by creating a profile which uses password.

> [!WARNING]
> This is still in early Proof of Concept stage. Any usage is at your own risk.

Previous:
```
auth    sufficient    pam_unix.so {if not "without-nullok":nullok}


password sufficient    pam_unix.so yescrypt shadow nullok use_authtok
```

After:
```
auth    optional    pam_secret.so translate_authtok
auth    sufficient    pam_unix.so {if not "without-nullok":nullok}

password   requisite    pam_secret.so auto_install translate_authtok
password   sufficient    pam_unix.so yescrypt shadow nullok use_authtok
```
