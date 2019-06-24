package main

import (
	"fmt"
	"os"

	"github.com/rubiojr/fcrypto"
)

const secret = "bar"
const file = "secret.conf"

func main() {
	needsSave := false

	if _, err := os.Stat(file); os.IsNotExist(err) {
		fmt.Println("Creating an empty file and adding 'foobar' to it")
		needsSave = true
		fcrypto.CreateFile(file, secret)
	} else {
		fmt.Println("Loading existing " + file)
	}

	buf, err := fcrypto.LoadFile(file, secret)
	if err != nil {
		panic(err)
	}

	if needsSave {
		buf.Write([]byte("foobar"))
		fmt.Printf("Encrypting the file %s with password '%s'\n", file, secret)
		err := fcrypto.SaveFile(buf, file, secret)
		if err != nil {
			fmt.Println(err)
		}
	} else {
		fmt.Println(buf.String())
	}
}
