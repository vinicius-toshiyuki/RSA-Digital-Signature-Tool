# RSA Signing with OAEP & SHA-3

Use this project to generate RSA keys, sign and verify files.

This project implements a C version of:

* RSA OAEP encryption, decryption, digital signing and signing verification.
* SHA-3 hashing algorithm.

SHA-3 based on [this implementation in JS](https://github.com/chrisveness/crypto), 
and reference from [Paar and Pelzl](http://professor.unisinos.br/linds/teoinfo/Keccak.pdf)
and [Keccak Team reference](https://keccak.team/files/Keccak-reference-3.0.pdf).

RSA & OAEP references from [DI Management](https://www.di-mgt.com.au/rsa_alg.html#keygen),
[RSA specifications v2.1](https://tools.ietf.org/html/rfc3447#section-7.1.1)
and [OAEP Wikipedia page](https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding).

Makefile from [Yuri Serka](https://github.com/yuriserka).

## Parameters Used

- A state width (b) of 1600 bits is used.
- A capacity (c) of 512 bits.
- Implying in a state depth of 64 (w) and 24 Keccak-f rounds.
- RSA bit length of 1024 bits.
- OAEP k0 constant of 11 bytes (88 bits).
- Implying in a message size of at most 117 bytes.

## Building and Running

### Dependencies

This project uses [GNU Multiple Precision](https://gmplib.org/) arithmetic library to generate
big random primes and operate with big integers.

All other dependencies are standard libraries.

### Build

Build the objects with

```
git clone https://github.com/vinicius-toshiyuki/rsa.git
cd rsa
make
```

### Run

And run with

```
./rsa.out [-c COMMAND OPTIONS | -h]
```

There are three commands: `genkeys`, `sign` and `verify`.
`genkeys` creates a key pair with extensions `.pk` and `.sk`, for public key and secret key, respectively.
`sign` takes a file and a RSA key as input and generate a output signature file.
`verify` takes a file, a signature file and a RSA key as input and prints either `Valid` or `Invalid` if the signature is valid or invalid, respectively.

More details on how to use these commands can be read using `./rsa.out -h`.

# Author

[Vinícius T M Sugimoto](https://github.com/vinicius-toshiyuki/rsa.git)

# License

MIT
