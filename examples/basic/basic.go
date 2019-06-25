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
