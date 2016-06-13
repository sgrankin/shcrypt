package main

import (
	"bytes"
	"crypto/md5"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

var (
	OPENSSH_RSA_KEY_SUBSTRING = "ssh-rsa AAAAB3NzaC1"
	OPENSSH_DSS_KEY_SUBSTRING = "ssh-dss AAAAB3NzaC1"
)

type SSHKey struct {
	Fingerprint       string
	PublicKey         *rsa.PublicKey
	PrivateKey        *rsa.PrivateKey
	RawPrivateKeyName string
}

func SSHKeyFromPublicKey(pubkey rsa.PublicKey) *SSHKey {
	return &SSHKey{
		PublicKey:   &pubkey,
		Fingerprint: getFingerPrint(pubkey),
	}
}

func SSHKeyFromPrivateKeyFile(keyname string, password PasswordReader) (*SSHKey, error) {
	key := SSHKey{RawPrivateKeyName: keyname}
	if err := key.LoadPrivateKey(password); err != nil {
		return nil, err
	}
	return &key, nil
}

func (k *SSHKey) LoadPrivateKey(password PasswordReader) (err error) {
	// With help from: https://stackoverflow.com/questions/14404757/how-to-encrypt-and-decrypt-plain-text-with-a-rsa-keys-in-go

	if k.PrivateKey != nil {
		return nil
	}

	rawKey, err := ioutil.ReadFile(k.RawPrivateKeyName)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(rawKey)
	if block == nil {
		return fmt.Errorf("unable to PEM-decode")
	}

	if got, want := block.Type, "RSA PRIVATE KEY"; got != want {
		return fmt.Errorf("Unknown key type %q.", got)
	}

	keyBytes := block.Bytes
	if strings.Contains(string(rawKey), "Proc-Type: 4,ENCRYPTED") {
		pw, err := password(keyname)
		if err != nil {
			return err
		}
		if keyBytes, err = x509.DecryptPEMBlock(block, pw); err != nil {
			return err
		}
	}

	key, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return err
	}
	k.PrivateKey = key
	k.PublicKey = &key.PublicKey
	k.Fingerprint = getFingerPrint(key.PublicKey)
	return nil
}

func LoadLocalSSHKeys(password PasswordReader) (map[string]SSHKey, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	// assume all private keys in .ssh have a .pub counterpart and find them
	sshDir := usr.HomeDir + "/.ssh/"

	files, err := ioutil.ReadDir(sshDir)
	if err != nil {
		return nil, err
	}

	keys := make(map[string]SSHKey)
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".pub") {
			continue
		}

		pubkey, err := ioutil.ReadFile(filepath.Join(sshDir, file.Name()))
		if err != nil {
			return nil, err
		}

		key, err := parseSSHPubKey(string(pubkey))
		if err != nil {
			continue // TODO: Debug print
		}

		privkeyname := filepath.Join(sshDir, strings.TrimSuffix(file.Name(), ".pub"))
		if !validSSHPrivKey(privkeyname) {
			continue
		}
		key.RawPrivateKeyName = privkeyname

		keys[key.Fingerprint] = *key
	}

	if len(keys) == 0 {
		idRsa := filepath.Join(sshDir, "id_rsa")
		if validSSHPrivKey(idRsa) {
			key, err := SSHKeyFromPrivateKeyFile(idRsa, password)
			if err != nil {
				return nil, err
			}
			keys[key.Fingerprint] = *key

		}
	}
	return keys, nil

}

func validSSHPrivKey(path string) bool {
	privkey, err := ioutil.ReadFile(path)
	if err != nil {
		return false
	}

	if strings.Contains(string(privkey), OPENSSH_RSA_KEY_SUBSTRING) {
		return false
	}

	return true
}

func parseSSHPubKey(key string) (*SSHKey, error) {
	/* Many users have DSS keys stored in addition to RSA keys.  When
	 * multiple keys are used, having an error for what is a valid SSH
	 * key, just not of type RSA, is a bit annoying, so we silence
	 * this error by default. */
	i := strings.Index(key, OPENSSH_DSS_KEY_SUBSTRING)
	if i >= 0 {
		return nil, fmt.Errorf("Skipping what looks like a DSS key to me.")
	}

	/* An RSA SSH key can have leading key options (including quoted
	 * whitespace) and trailing comments (including whitespace).  We
	 * take a short cut here and assume that if it contains the known
	 * RSA pattern, then that field must be the actual key.  This
	 * would be a false assumption if one of the comments or options
	 * contained that same pattern, but anybody who creates such a key
	 * can go screw themselves. */
	i = strings.Index(key, OPENSSH_RSA_KEY_SUBSTRING)
	if i < 0 {
		return nil, fmt.Errorf("Not an ssh RSA public key: '%v'", key)
	}

	fields := strings.Split(key[i:], " ")
	decoded := decode(fields[1])
	if len(decoded) < 1 {
		return nil, fmt.Errorf("Unable to decode key.")
	}

	/* Based on:
	 * http://cpansearch.perl.org/src/MALLEN/Convert-SSH2-0.01/lib/Convert/SSH2.pm
	 * https://gist.github.com/mahmoudimus/1654254,
	 * http://golang.org/src/pkg/crypto/x509/x509.go
	 *
	 * See also: http://www.netmeister.org/blog/ssh2pkcs8.html
	 *
	 * The key format is base64 encoded tuples of:
	 * - four bytes representing the length of the next data field
	 * - the data field
	 *
	 * In practice, for an RSA key, we get:
	 * - four bytes [0 0 0 7]
	 * - the string "ssh-rsa" (7 bytes)
	 * - four bytes
	 * - the exponent
	 * - four bytes
	 * - the modulus
	 */

	var k rsa.PublicKey
	n := 0
	for len(decoded) > 4 {
		var dlen uint32
		bbuf := bytes.NewReader(decoded[:4])
		err := binary.Read(bbuf, binary.BigEndian, &dlen)
		if err != nil {
			fmt.Printf("%v", err)
			continue
		}

		chunklen := int(dlen) + 4
		if len(decoded) < chunklen {
			return nil, fmt.Errorf("Invalid data while trying to extract public key. %v", key)
		}

		data := decoded[4:chunklen]
		decoded = decoded[chunklen:]

		switch n {
		case 0:
			if ktype := fmt.Sprintf("%s", data); ktype != "ssh-rsa" {
				return nil, fmt.Errorf("Unsupported key type (%v).", ktype)
			}
		case 1:
			i := new(big.Int)
			i.SetString(fmt.Sprintf("0x%v", hex.EncodeToString(data)), 0)
			k.E = int(i.Int64())
		case 2:
			i := new(big.Int)
			/* The value in this field is signed, so the first
			 * byte should be 0, so we strip it. */
			i.SetString(fmt.Sprintf("0x%v", hex.EncodeToString(data[1:])), 0)
			k.N = i
		}
		n++
	}

	return SSHKeyFromPublicKey(k), nil
}

func decode(input string) (decoded []byte) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to decode input:\n%v\n%v\n",
			input, err)
	}
	return
}

func getFingerPrint(pubkey rsa.PublicKey) (fp string) {

	/* The fingerprint of a public key is just the md5 of the raw
	 * data.  That is, we combine:
	 *
	 * [0 0 0 7]  -- length of next chunk
	 * "ssh-rsa"
	 * 4 bytes    -- length of next chunk
	 * the public key exponent
	 * 4 bytes    -- length of next chunk
	 * 0          -- first byte of modulus, since it's signed
	 * the public key modulus
	 */
	var b bytes.Buffer
	b.Write([]byte{0, 0, 0, 7})
	b.Write([]byte("ssh-rsa"))

	/* exponent */
	x := new(big.Int)
	x.SetString(fmt.Sprintf("%d", pubkey.E), 0)
	b.Write([]byte{0, 0, 0, byte(len(x.Bytes()))})
	b.Write(x.Bytes())

	/* modulus */
	tmpbuf := make([]byte, 0)
	mlen := len(pubkey.N.Bytes()) + 1
	x.SetString(fmt.Sprintf("%d", mlen), 0)
	xlen := len(x.Bytes())
	for i := 0; i < xlen; i++ {
		tmpbuf = append(tmpbuf, 0)
	}
	tmpbuf = append(tmpbuf, x.Bytes()...)

	/* append one zero byte to indicate signedness */
	tmpbuf = append(tmpbuf, 0)

	b.Write(tmpbuf)
	b.Write(pubkey.N.Bytes())

	fingerprint := md5.New()
	fingerprint.Write(b.Bytes())
	return base64.RawURLEncoding.EncodeToString(fingerprint.Sum(nil))
}
