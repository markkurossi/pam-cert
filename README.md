# pam-cert

Pluggable Authentication Module (PAM) using certificate authentication.

![PAM Cert](pam-cert.png)

# Installation

Copy `pam_cert.so` to `/lib/x86_64-linux-gnu/security/pam_cert.so`

```sh
$ sudo cp module/pam_cert.so /lib/x86_64-linux-gnu/security/pam_cert.so
```

Edit PAM configuration to authenticate users with `pam_cert.so`:

```sh
$ grep $ grep pam_cert /etc/pam.d/*
/etc/pam.d/common-auth:auth sufficient pam_cert.so
```

Generate CA keypair:

```sh
$ cmd/ca/ca make-keys
$ ls -l ca.*
-rw-r--r--  1 mtr  staff  88 May  2 06:40 ca.priv
-rw-r--r--  1 mtr  staff  44 May  2 06:40 ca.pub
```

Install `ca.pub` to target:

```sh
$ sudo cp ca.pub /etc/ca.pub
```

# Usage

Login to target:

```
Ubuntu 20.04.1 LTS ubuntu tty03

ubuntu login: mtr
Username   : mtr
Hostname   : ubuntu
Time       : 2021-05-02T03:44:52+0000
Challenge  : AAAAA210cgAAAAZ1YnVudHVgjiA0
Certificate:
```

Generate token with ca:

```
$ cmd/ca/ca -c AAAAA210cgAAAAZ1YnVudHVgjiA0 sign
challenge: 2021-05-02T06:44:52+03:00 mtr@ubuntu
Certificate: AAAAIAAAAANtdHIAAAADbXRyAAAABnVidW50dWCOIGJgjiA0AAAAQNp9wAqWvDhjRiZUMqlfqR9vdpv6S4l8u6trAMIQNDTxNJaq4uwX8L2s88WTjh6n8URbC4xwik6NnGvNZxdXnw4=
```

Complete login by providing certificate to the login prompt:

```
Certificate: AAAAIAAAAANtdHIAAAADbXRyAAAABnVidW50dWCOILhgjiA0AAAAQIpwV25mDcsyKXBnZHYWsHWBlM/8dT8pO8AHxi5EEa4frlM0KgRh8f6s6Zji5q+6Xq2UxzU8MSOikR7GBS8WeQM=
token      : 2021-05-02T03:44:52+0000 mtr => mtr@ubuntu
Valid certificate for user mtr
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-65-generic x86_64)

mtr@ubuntu:~$
```

# References

 - The [Ed25519](module/ed25519) is from [github.com/orlp/ed25519](https://github.com/orlp/ed25519).
 - The [Base64](module/base64.md) is from [FreeBSD wpa_supplicant](http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c).
