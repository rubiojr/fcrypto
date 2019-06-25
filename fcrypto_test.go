package fcrypto

import (
	"bytes"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const secret = "secret"
const file = "testdata/test.txt"

func TestEncrypt(t *testing.T) {
	SaveFile(bytes.NewBufferString("foobar"), "testdata/test.txt", "test")
	_, err := os.Stat("testdata/test.txt")
	assert.Nil(t, err)
	content := `# Encrypted fcrypto file

FCRYPTO_V0:`

	fc, err := ioutil.ReadFile("testdata/test.txt")
	assert.Equal(t, true, strings.Contains(string(fc), content))
}

func TestDecrypt(t *testing.T) {
	SaveFile(bytes.NewBufferString("foobar"), "testdata/test.txt", "secret")
	_, err := os.Stat("testdata/test.txt")
	assert.Nil(t, err)

	res, err := LoadFile("testdata/test.txt", "secret")
	assert.Nil(t, err)
	assert.Equal(t, "foobar", res.String())
}
