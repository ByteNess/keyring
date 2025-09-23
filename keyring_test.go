package keyring_test

import (
	"log"

	"github.com/byteness/keyring"
)

func ExampleOpen() {
	// Use the best keyring implementation for your operating system
	kr, err := keyring.Open(keyring.Config{
		ServiceName:    "my-service",
		UseBiometrics:  true,
		TouchIDAccount: "cc.byteness.aws-vault.biometrics",
		TouchIDService: "aws-vault",
	})
	if err != nil {
		log.Fatal(err)
	}

	v, err := kr.Get("llamas")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("llamas was %v", v)
}
