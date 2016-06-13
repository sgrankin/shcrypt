# shcrypt
shcrypt is a tool to let you encrypt and decrypt messages using SSH keys.  It finds public SSH keys on GitHub (https://github.com/username.keys) and supports encrypting messages targetted to multiple recipient keys.

## Usage

```sh
$ go get github.com/sgrankin/shcrypt

$ echo hello world | shcrypt -u sgrankin  | shcrypt -d
hello world

$ shcrypt -h
Usage of shcrypt:
  -K path
    	encrypt to SSH public key at path
  -V	print version and exit
  -d	decrypt
  -f path
    	file path to encrypt or decrypt (default "-")
  -k path
    	decrypt with SSH private key at path
  -p source
    	decrypt private SSH key with password from source: pass:passphrase, env:envvar, file:filename
  -u username
    	username of recipient
```

## Who wrote this tool?
This tool started as a small patch to [jass][jass] to let it read all local private ssh keys, but turned into a prolonged exercise in code golf.  The changes, roughly:
 - removed support for all methods of fetching SSH keys other than GitHub
 - encryption changed to [AES256-GCM](https://golang.org/src/crypto/cipher/example_test.go)
 - serialization format changed to [edn](https://github.com/edn-format/edn)

Most of the interesting code, including SSH everything to do with SSH, remained the same (a verbatim copy of the original) so credit is due entirely to the original.  Please see info below:

[jass(1)][jass] was originally written by Jan Schaumann (jschauma@netmeister.org) in
April 2013.

You can read more about it here:
* http://www.netmeister.org/blog/sharing-secrets-using-ssh-keys.html
* http://www.netmeister.org/blog/jass.html
* https://www.netmeister.org/blog/ssh2pkcs8.html

[jass]: https://github.com/jschauma/jass
