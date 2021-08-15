 `nlcc` 
========
NIST Lightweight Competition CLI.  
Compile any of the NIST lightweight crypto competition entries into a usable
CLI tool.

```
!             this tool is a 'toy'              !
!        it is not designed to be secure        !
! do not use this for any sensitive information !
```

 Dependencies 
--------------
* libsodium
* api.h, encrypt.c from a competition entry's source

 Building 
----------
1. Copy api.h, and encrypt.c from your chosen algorithm's source to the repo
   root
2. Run `make`

 Usage 
-------
```
nlcc [-h] [-k key_file] [-n nonce_file] [-a ad] [-m message|-d ciphertext]
where:
    -h               shows help
    -k key_file      file to read key from
    -n nonce_file    file to read nonce from
    -a ad            string of associated data
    -m message       message to encrypt
    -d ciphertext    ciphertext (hex encoded) to decrypt
```

Note:

* Outputs are hex encoded and are tailed with the output size (in bits)
* Plaintext contains a decoded representation in quotations

 Examples 
----------
Encryption:

```console
$ ./nlcc -k ./file -m "testing message" -a "adadadadad"
Key   = ffffffffffffffffffffffffffffffff (128)
Nonce = 000000000000000000000000 (96)
AD    = 61646164616461646164 (80)
PT    = 74657374696e67206d657373616765 ("testing message") (120)
CT    = 87e649bf2c3e6c83cbb1ee7120c419a1f58b03b0386258
```

Decryption of above ciphertext (same key, same ad):

```console
$ ./nlcc -k ./file -a "adadadadad" -d "87e649bf2c3e6c83cbb1ee7120c419a1f58b03b0386258"
Key   = ffffffffffffffffffffffffffffffff (128)
Nonce = 000000000000000000000000 (96)
AD    = 61646164616461646164 (80)
CT    = 87e649bf2c3e6c83cbb1ee7120c419a1f58b03b0386258 (184)
PT    = 74657374696e67206d657373616765 ("testing message") (120)
```

 Todo
------
* encrypt/decrypt from stdin/stdout
* load associated data from file
* better command-line flags
* script to download and compile every competition entry into a CLI tool
