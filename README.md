# fcrypto

File encryption/decryption extracted from Nick Craig-Wood's [rclone source code](https://github.com/ncw/rclone).

> rclone uses nacl secretbox which in turn uses XSalsa20 and Poly1305 to encrypt and authenticate your configuration with secret-key cryptography. The password is SHA-256 hashed, which produces the key for secretbox. The hashed password is not stored.
>
> While this provides very good security, we do not recommend storing your encrypted rclone configuration in public if it contains sensitive information, maybe except if you use a very strong password.

See [file encryption in rclone docs.](https://github.com/ncw/rclone/blob/976a020a2f4814ab32686bd47870ddb45699950a/docs/content/docs.md)
