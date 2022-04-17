package main

import (
	"flag"
	"fmt"
	"github.com/rendicott/uggsec"
	"log"
	"os"
)

var (
	message        = flag.String("message", "ovaltine", "string to encrypt")
	filename       = flag.String("filename", "cookies.txt", "file to write and read encrypted data to/from")
	passwordEnvVar = flag.String("env-var", "UGGSECP", "env var that stores encryption/decryption password in the event that keyring doesn't work")
	encryptFlag    = flag.Bool("encrypt", false, "whether to encrypt string and write to disk")
	decryptFlag    = flag.Bool("decrypt", false, "whether to decrypt file print screen")
	newPassword    = flag.Bool("new-password", false, "creates a new password and repeats back to STDOUT. Usefull for setting ENV var")
)

func main() {
	flag.Parse()
	if *newPassword {
		fmt.Println(uggsec.NewVaultPassword())
		os.Exit(0)
	}
	params := uggsec.VaultInput{
		Filename: *filename,
		Service:  "ugglyc",
		User:     "browser",
		//PasswordEnvVar: "", // must contain 32 byte password
	}
	vault, err := uggsec.InitSmart(&params)
	if err != nil {
		log.Printf("error initiating keyring: %v", err)
		log.Print("using ENV var instead")
		// must contain 32 byte string. Defaults to UGGSECP if left blank
		params.PasswordEnvVar = *passwordEnvVar
		vault, err = uggsec.InitSmart(&params)
	}
	if *encryptFlag {
		err = vault.Write(*message)
		if err != nil {
			log.Fatal(err)
		}
		log.Print("successfully encrypted message")
	}
	if *decryptFlag {
		text, err := vault.Read()
		if err != nil {
			log.Fatal(err)
		}
		log.Print("successfully decrypted message")
		fmt.Println(text)
	}
}
