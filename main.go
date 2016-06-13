/*
 * Copyright (c) 2013, Twitter. Inc.
 * Copyright (c) 2015, Yahoo, Inc.
 *
 * Originally written by Jan Schaumann <jschauma@twitter.com> in April
 * 2013 in shell; re-written in Go in December 2013.
 *
 * Currently maintained by Jan Schaumann <jschauma@yahoo-inc.com>.
 *
 * This little program allows you to easily share secrets with other users
 * by way of ssh pubkeys.
 */

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/sgrankin/shcrypt/flagutil"
	"gopkg.in/edn.v1"
)

const (
	EXIT_FAILURE = 1
	EXIT_SUCCESS = 0

	PROGNAME = "shcrypt"
	VERSION  = "1.0"

	GITHUB_URL = "https://github.com/%s.keys"
)

var (
	recipients flagutil.StringListValue
	pubkeyname string
	filename   string

	doDecrypt bool
	keyname   string
	password  string

	doVersion bool
)

func init() {
	flag.Var(&recipients, "u", "`username` of recipient")
	flag.StringVar(&pubkeyname, "K", "", "encrypt to SSH public key at `path`")

	flag.StringVar(&filename, "f", "-", "file `path` to encrypt or decrypt")

	flag.BoolVar(&doDecrypt, "d", false, "decrypt")
	flag.StringVar(&keyname, "k", "", "decrypt with SSH private key at `path`")
	flag.StringVar(&password, "p", "", "decrypt private SSH key with password from `source`: pass:passphrase, env:envvar, file:filename")
	flag.BoolVar(&doVersion, "V", false, "print version and exit")
}

func main() {
	log.SetFlags(0)

	flag.Parse()
	if filename == "-" {
		filename = "/dev/stdin"
	}

	if doVersion {
		fmt.Printf("%v version %v", PROGNAME, VERSION)
	} else if doDecrypt {
		data, err := decrypt(readFile(filename), keyname, password)
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(data)
	} else {
		if len(recipients)+len(pubkeyname) == 0 {
			flag.Usage()
			log.Fatal("Error: at least one of -u or -K is required for encryption")
		}
		encrypted, err := encrypt(readFile(filename), recipients, string(readFile(pubkeyname)))
		if err != nil {
			log.Fatal(err)
		}
		os.Stdout.Write(encrypted)
	}
}

func readFile(filename string) []byte {
	if len(filename) == 0 {
		return nil
	}

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	return data
}

type Payload struct {
	Keys   map[string][]byte
	Mesage []byte
}

func encrypt(data []byte, recpipents []string, pubkey string) ([]byte, error) {
	keys, err := getGithubKeys(recipients)
	if err != nil {
		return nil, err
	}
	if len(pubkey) > 0 {
		keys = append(keys, pubkey)
	}

	pubkeys, err := parseSSHPubKeys(keys)
	if err != nil {
		return nil, err
	}

	skey, err := getRandomBytes(KeySize)
	if err != nil {
		return nil, err
	}

	cipherSkeys, err := EncryptSessionKey(skey, pubkeys)
	if err != nil {
		return nil, err
	}

	cipherData, err := EncryptMessage(data, skey)
	if err != nil {
		return nil, err
	}

	return edn.Marshal(Payload{cipherSkeys, cipherData})
}

func getGithubKeys(recipients []string) ([]string, error) {
	keys := make([]string, 0)
	for _, recipient := range recipients {
		recipientKeys, err := getGithubUserKeys(recipient)
		if err != nil {
			return nil, err
		}
		keys = append(keys, recipientKeys...)
	}
	return keys, nil
}

func getGithubUserKeys(recipient string) ([]string, error) {
	url := fmt.Sprintf(GITHUB_URL, recipient)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error getting %v: %v", url, resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(body), "\n"), nil
}

func parseSSHPubKeys(keys []string) ([]SSHKey, error) {
	pubkeys := make([]SSHKey, 0)
	for _, key := range keys {
		if len(key) == 0 {
			continue
		}

		pubkey, err := parseSSHPubKey(key)
		if err != nil {
			return nil, err
		}
		if pubkey.PublicKey.E > 0 {
			pubkeys = append(pubkeys, *pubkey)
		}
	}
	return pubkeys, nil
}

func decrypt(data []byte, keyname string, passwordSpec string) ([]byte, error) {
	password, err := NewPasswordReader(passwordSpec)
	if err != nil {
		return nil, err
	}
	keys, err := loadSSHKeys(keyname, password)
	if err != nil {
		return nil, err
	}

	var payload Payload
	err = edn.Unmarshal(data, &payload)
	if err != nil {
		return nil, err
	}

	for fingerprint, encryptedSessionKey := range payload.Keys {
		if key, ok := keys[fingerprint]; ok {
			if key.PrivateKey == nil {
				if err := key.LoadPrivateKey(password); err != nil {
					return nil, err
				}
			}
			skey, err := DecryptSessionKey(encryptedSessionKey, *key.PrivateKey)
			if err != nil {
				return nil, err
			}
			return DecryptMessage(payload.Mesage, skey)
		}
	}
	return nil, fmt.Errorf("Data was not encrypted for any known keys")
}

func loadSSHKeys(keyname string, password PasswordReader) (map[string]SSHKey, error) {
	if len(keyname) > 0 {
		key, err := SSHKeyFromPrivateKeyFile(keyname, password)
		if err != nil {
			return nil, err
		}
		return map[string]SSHKey{key.Fingerprint: *key}, nil
	} else {
		return LoadLocalSSHKeys(password)
	}
}
