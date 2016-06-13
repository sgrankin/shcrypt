package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

type PasswordReader func(context string) (secret []byte, err error)

func NewPasswordReader(spec string) (password PasswordReader, err error) {
	var source string
	var passin []string

	err = fmt.Errorf("Invalid argument for passphrase: %v", spec)
	if len(spec) == 0 {
		source = "tty"
	} else {
		passin = strings.SplitN(spec, ":", 2)
		if len(passin) < 2 {
			return nil, err
		}
		source = passin[0]
	}

	switch source {
	case "tty":
		return func(context string) ([]byte, error) { return getpassFromUser(context) }, nil
	case "pass":
		return func(string) ([]byte, error) { return []byte(passin[1]), nil }, nil
	case "file":
		return func(string) ([]byte, error) { return getpassFromFile(passin[1]) }, nil
	case "env":
		return func(string) ([]byte, error) { return getpassFromEnv(passin[1]) }, nil
	default:
		return nil, err
	}
}

func getpassFromEnv(varname string) ([]byte, error) {
	pass := []byte(os.Getenv(varname))
	if len(pass) < 1 {
		return nil, fmt.Errorf("Environment variable '%v' not set.", varname)
	}
	return pass, nil
}

func getpassFromFile(fname string) ([]byte, error) {
	file, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		return []byte(scanner.Text()), nil
	}
	return nil, fmt.Errorf("no password found in %v", fname)
}

func getpassFromUser(context string) ([]byte, error) {
	fmt.Printf("enter password for %v:", context)
	pass, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return nil, err
	}
	return pass, nil
}
