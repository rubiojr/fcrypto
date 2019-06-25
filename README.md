# fcrypto

[![Build Status](https://travis-ci.com/rubiojr/fcrypto.svg?branch=master)](https://travis-ci.com/rubiojr/fcrypto)

File encryption/decryption extracted from Nick Craig-Wood's [rclone source code](https://github.com/ncw/rclone).

> rclone uses nacl secretbox which in turn uses XSalsa20 and Poly1305 to encrypt and authenticate your configuration with secret-key cryptography. The password is SHA-256 hashed, which produces the key for secretbox. The hashed password is not stored.
>
> While this provides very good security, we do not recommend storing your encrypted rclone configuration in public if it contains sensitive information, maybe except if you use a very strong password.

See [file encryption in rclone docs.](https://github.com/ncw/rclone/blob/976a020a2f4814ab32686bd47870ddb45699950a/docs/content/docs.md)

```go
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/rubiojr/fcrypto"
)

const secret = "bar"
const file = "secret.conf"

func main() {

	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Println("Saving a file with 'foobar'")
		fcrypto.SaveFile(bytes.NewBufferString("foobar"), file, secret)
	} else {
		fmt.Println("Loading existing " + file)
	}

	buf, err := fcrypto.LoadFile(file, secret)
	if err != nil {
		panic(err)
	}
	fmt.Println("Decrypting the file...")
	fmt.Println("File content: " + buf.String())
}
```
