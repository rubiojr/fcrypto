// Package config reads, writes and edits the config file and deals with command line flags
package fcrypto

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/text/unicode/norm"
)

// Global
var (
	// output of prompt for password
	PasswordPromptOutput = os.Stderr
)

// LoadFile will loads an encrypted  file and decrypts it
func LoadFile(path, pwd string) (*bytes.Buffer, error) {
	configKey, _ := genFilePassword(pwd)
	b, err := ioutil.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New(fmt.Sprintf("File %s not found", path))
		}
		return nil, err
	}
	// Find first non-empty line
	r := bufio.NewReader(bytes.NewBuffer(b))
	for {
		line, _, err := r.ReadLine()
		if err != nil {
			if err == io.EOF {
				return bytes.NewBuffer(b), err
			}
			return nil, err
		}
		l := strings.TrimSpace(string(line))
		if len(l) == 0 || strings.HasPrefix(l, ";") || strings.HasPrefix(l, "#") {
			continue
		}
		// First non-empty or non-comment must be ENCRYPT_V0
		if l == "FCRYPTO_V0:" {
			break
		}
		return bytes.NewBuffer(b), nil
	}

	// Encrypted content is base64 encoded.
	dec := base64.NewDecoder(base64.StdEncoding, r)
	box, err := ioutil.ReadAll(dec)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to load base64 encoded data")
	}
	if len(box) < 24+secretbox.Overhead {
		return nil, errors.New("File data too short")
	}

	var out []byte
	for {
		// Nonce is first 24 bytes of the ciphertext
		var nonce [24]byte
		copy(nonce[:], box[:24])
		var key [32]byte
		copy(key[:], configKey[:32])

		// Attempt to decrypt
		var ok bool
		out, ok = secretbox.Open(nil, box[24:], &nonce, &key)
		if ok {
			break
		}

		// Retry
		fmt.Errorf("Couldn't decrypt configuration, most likely wrong password.")
		configKey = nil
	}
	return bytes.NewBuffer(out), err
}

// checkPassword normalises and validates the password
func checkPassword(password string) (string, error) {
	if !utf8.ValidString(password) {
		return "", errors.New("password contains invalid utf8 characters")
	}

	// Normalize to reduce weird variations.
	password = norm.NFKC.String(password)
	if len(password) == 0 {
		return "", errors.New("no characters in password")
	}
	return password, nil
}

// GetPassword asks the user for a password with the prompt given.
func GetPassword(prompt string) string {
	_, _ = fmt.Fprintln(PasswordPromptOutput, prompt)
	for {
		_, _ = fmt.Fprint(PasswordPromptOutput, "password:")
		password := ReadPassword()
		password, err := checkPassword(password)
		if err == nil {
			return password
		}
		_, _ = fmt.Fprintf(os.Stderr, "Bad password: %v\n", err)
	}
}

// ReadPassword for OSes which are supported by golang.org/x/crypto/ssh/terminal
// See https://github.com/golang/go/issues/14441 - plan9
//     https://github.com/golang/go/issues/13085 - solaris
// ReadPassword reads a password without echoing it to the terminal.
func ReadPassword() string {
	stdin := int(os.Stdin.Fd())
	if !terminal.IsTerminal(stdin) {
		return ReadLine()
	}
	line, err := terminal.ReadPassword(stdin)
	_, _ = fmt.Fprintln(os.Stderr)
	if err != nil {
		log.Fatalf("Failed to read password: %v", err)
	}
	return string(line)
}

// ChangePassword will query the user twice for the named password. If
// the same password is entered it is returned.
func ChangePassword(name string) string {
	for {
		a := GetPassword(fmt.Sprintf("Enter %s password:", name))
		b := GetPassword(fmt.Sprintf("Confirm %s password:", name))
		if a == b {
			return a
		}
		fmt.Println("Passwords do not match!")
	}
}

func genFilePassword(password string) ([]byte, error) {
	password, err := checkPassword(password)
	if err != nil {
		return nil, err
	}
	// Create SHA256 has of the password
	sha := sha256.New()
	_, err = sha.Write([]byte("[" + password + "][fcrypto]"))
	if err != nil {
		return nil, err
	}
	return sha.Sum(nil), nil
}

// SaveFile saves the encrypted configuration file.
func SaveFile(buf *bytes.Buffer, path, pwd string) error {
	f, err := os.Create(path)
	if err != nil {
		return errors.Errorf("Failed to create temp file for new config: %v", err)
	}

	configKey, _ := genFilePassword(pwd)
	if err != nil {
		fmt.Errorf("Fatal %v", err)
	}
	_, _ = fmt.Fprintln(f, "# Encrypted fcrypto file")
	_, _ = fmt.Fprintln(f, "")
	_, _ = fmt.Fprintln(f, "FCRYPTO_V0:")

	// Generate new nonce and write it to the start of the ciphertext
	var nonce [24]byte
	n, _ := rand.Read(nonce[:])
	if n != 24 {
		return errors.Errorf("nonce short read: %d", n)
	}
	enc := base64.NewEncoder(base64.StdEncoding, f)
	_, err = enc.Write(nonce[:])
	if err != nil {
		return errors.Errorf("Failed to write file: %v", err)
	}

	var key [32]byte
	copy(key[:], configKey[:32])

	b := secretbox.Seal(nil, buf.Bytes(), &nonce, &key)
	_, err = enc.Write(b)
	if err != nil {
		return errors.Errorf("Failed to write to file: %v", err)
	}
	_ = enc.Close()

	err = f.Close()
	if err != nil {
		return errors.Errorf("Failed to file: %v", err)
	}

	var fileMode os.FileMode = 0600
	info, err := os.Stat(path)
	if err != nil {
		//fmt.Printf("Using default permissions for config file: %v", fileMode)
	} else if info.Mode() != fileMode {
		//fmt.Printf("Keeping previous permissions for config file: %v", info.Mode())
		fileMode = info.Mode()
	}

	err = os.Chmod(f.Name(), fileMode)
	if err != nil {
		fmt.Errorf("Failed to set permissions on config file: %v", err)
	}

	return nil
}

// ReadLine reads some input
var ReadLine = func() string {
	buf := bufio.NewReader(os.Stdin)
	line, err := buf.ReadString('\n')
	if err != nil {
		log.Fatalf("Failed to read line: %v", err)
	}
	return strings.TrimSpace(line)
}
