// Package uggsec provides objects and methods for securely storing contents
// to files using encryption. The decryption password is either stored in the
// OS keyring or in an ENV variable that the user specifies. 
package uggsec

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"github.com/zalando/go-keyring"
	"fmt"
	"io/ioutil"
	"errors"
	"math/rand"
	"strings"
	"time"
	"os"
)

var (
	bytes = []byte{35, 46, 57, 24, 85, 35, 24, 74, 87, 35, 88, 98, 66, 32, 14, 05}
	keySize = 32
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789")
)

type VaultInput struct {
	// For systems that support KeyRings this is the label
	// that the password will be stored under in the keyring
	Service, User string

	// On systems where no keyring is available this package
	// use of a password stored in this environment
	// variable. Must contain predetermined length byte string 
	// as defined by keySize in this package. This
	// package has a helper function NewPassword which honors 
	// keySize and can be used to set your ENV var's contents.
	PasswordEnvVar string

	// Filename of the encrypted file that should be used for 
	// storing this vault's contents
	Filename string
}

// Vault provides methods for reading and writing
// encrypted contents to files. Use the Init methods provided
// by this package to obtain a Vault object.
type Vault struct {
	service, user string
	filename string
	passwordEnvVar string
	keyring bool
}

// InitSmart tries to determine the best method of Vault instantiation
// based on the provided input param struct.
func InitSmart(i *VaultInput) (*Vault, error) {
	if i.PasswordEnvVar != "" {
		return(InitEnvVar(i))
	}
	return InitKeyring(i)
}

// InitKeyring initializes a new or existing vault so that the 
// Read and Write methods can be called on the returned vault. It
// attempts to retrieve a password from the OS keyring stored under
// the provided Service and User label. If no password can be retrieved
// then one is created. If no existing vault file can be found then one
// is created. If it fails to load the OS keyring then an error is returned
// so the user could instead call the NewPassword and InitEnvVar methods as
// an alternative.  
func InitKeyring(i *VaultInput) (*Vault, error) {
	var err error
	v := Vault{
		service: i.Service,
		user: i.User,
		filename: i.Filename,
	}
	// see if existing keyring password exists
	_, err = keyring.Get(v.service, v.user)
	if err != nil {
		if strings.Contains(err.Error(), "secret not found in keyring") {
			// means keyring works but no password for this service/user yet
			err = initKeyring(v.service, v.user)
			if err != nil {
				return &v, err
			}
			v.keyring = true
		} else {
			return &v, err
		}
	}
	v.keyring = true
	// now try to load file
	_, err = v.loadFromDisk()
	if err != nil {
		if strings.Contains(err.Error(), "system cannot find the file specified") {
			// create new file by writing nothing to it
			err = v.Write("")
		}
		return &v, err
	}
	return &v, err
}

// InitEnvVar initializes a new or existing vault using the password stored
// in the provided environment variable. The returned vault can
// then be written and read using the Write and Read methods.
func InitEnvVar(i *VaultInput) (*Vault, error) {
	var err error
	v := Vault{
		filename: i.Filename,
		passwordEnvVar: i.PasswordEnvVar,
	}
	_, err = v.getPassword()
	return &v, err
}

// NewPassword returns a password that can be used for interacting
// with vaults. Since this package's password requirements are strict
// this is a useful helper function when doing things like setting 
// the contents of ENV vars on systems that don't support keyring.
func NewVaultPassword() (string) {
	rand.Seed(time.Now().UnixNano())
	return(randStringRunes(keySize))
}

// Write writes the contents of the input string into the 
// filename associated with the vault and encrypts it using
// the password retrieval mechanism available to the vault
// (e.g., keyring or ENV var) then returns any errors it
// encounters. It overrides the entire contents of the file.
// If no file exists then one is created.
func (v *Vault) Write(contents string) (err error) {
	password, err := v.getPassword()
	if err != nil {
		return err
	}
	encrypted, err := encrypt(contents, password)
	if err != nil {
		return err
	}
	b := []byte(encrypted)
	err = ioutil.WriteFile(v.filename, b, 0600)
	return err
}


// Read returns the decrypted contents of the filename
// associated with the vault using whatever password
// retreival mechanisms are avaialble to the vault 
// (e.g., keyring or ENV var)
func (v *Vault) Read() (contents string, err error) {
	return v.loadFromDisk()
}

func (v *Vault) getPasswordEnv() (password string, err error) {
	password = os.Getenv(v.passwordEnvVar)
	if password == "" {
		msg := fmt.Sprintf("no password found in %s env var", v.passwordEnvVar)
		err = errors.New(msg)
	}
	return password, err
}

func (v *Vault) getPasswordKeyring() (password string, err error) {
	return(keyring.Get(v.service, v.user))
}


func (v *Vault) getPassword() (password string, err error) {
	if v.keyring {
		password, err = v.getPasswordKeyring()
	} else {
		password, err = v.getPasswordEnv()
	}
	return password, err
}

func (v *Vault) loadFromDisk() (contents string, err error) {
	data, err := ioutil.ReadFile(v.filename)
	if err != nil {
		return contents, err
	}
	password, err := v.getPassword()
	if err != nil {
		return contents, err
	}
	return decrypt(string(data), password)
}


func encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func decode(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func encrypt(text, password string) (string, error) {
	block, err := aes.NewCipher([]byte(password))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, bytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return encode(cipherText), nil
}

func decrypt(encrypted, password string) (string, error) {
	block, err := aes.NewCipher([]byte(password))
	if err != nil {
		return "", err
	}
	cipherText := decode(encrypted)
	cfb := cipher.NewCFBDecrypter(block, bytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}

func initKeyring(service, user string) (err error) {
	err = keyring.Set(service, user, NewVaultPassword())
	return err
}

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

