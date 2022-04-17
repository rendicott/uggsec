# uggsec

# Go Docs
```
package uggsec // import "github.com/rendicott/uggsec"

Package uggsec provides objects and methods for securely storing contents to
files using encryption. The decryption password is either stored in the OS
keyring or in an ENV variable that the user specifies.

FUNCTIONS

func NewVaultPassword() string
    NewPassword returns a password that can be used for interacting with vaults.
    Since this package's password requirements are strict this is a useful
    helper function when doing things like setting the contents of ENV vars on
    systems that don't support keyring.


TYPES

type Vault struct {
	// Has unexported fields.
}
    Vault provides methods for reading and writing encrypted contents to files.
    Use the Init methods provided by this package to obtain a Vault object.

func InitEnvVar(i *VaultInput) (*Vault, error)
    InitEnvVar initializes a new or existing vault using the password stored in
    the provided environment variable. The returned vault can then be written
    and read using the Write and Read methods.

func InitKeyring(i *VaultInput) (*Vault, error)
    InitKeyring initializes a new or existing vault so that the Read and Write
    methods can be called on the returned vault. It attempts to retrieve a
    password from the OS keyring stored under the provided Service and User
    label. If no password can be retrieved then one is created. If no existing
    vault file can be found then one is created. If it fails to load the OS
    keyring then an error is returned so the user could instead call the
    NewPassword and InitEnvVar methods as an alternative.

func InitSmart(i *VaultInput) (*Vault, error)
    InitSmart tries to determine the best method of Vault instantiation based on
    the provided input param struct.

func (v *Vault) Read() (contents string, err error)
    Read returns the decrypted contents of the filename associated with the
    vault using whatever password retreival mechanisms are avaialble to the
    vault (e.g., keyring or ENV var)

func (v *Vault) Write(contents string) (err error)
    Write writes the contents of the input string into the filename associated
    with the vault and encrypts it using the password retrieval mechanism
    available to the vault (e.g., keyring or ENV var) then returns any errors it
    encounters. It overrides the entire contents of the file. If no file exists
    then one is created.

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
```
