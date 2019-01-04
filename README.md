# cert-on-block
## About
This program consists of a CLI for issuing, retrieving and revoking digital
certificates on top of the Ethereum blockchain, as well as a few other
utilities, like signing files and checking signatures, and generating key
pairs.

This program was developed during a scientific research and should not be used
for real life applications.

## Installation
After downloading the project, use
`pip3 -r requirements.txt`
to install the required dependencies.

## Usage
To run the program, simply run the `main.py` with one of the sub-commands.
Running it with no sub-commands and with the `-h` flag, gives a brief
description of each one.

There are 6 sub-commands that can be used:

* `issue`
* `sign`
* `check-sig`
* `get-cert`
* `revoke-cert`
* `gen-keys`

Following is a description of each command and its parameters.

### `issue` command
#### Description
The `issue` command is used for issuing a digital certificate on the Ethereum
blockchain.
The digital certificate consists of a transaction on the Ethereum blockchain
from the address of a CA to the address of the user, and containing all of the
certificate data inside the data field.

#### Parameters
* `--address`: Specifies the address on the blockchain to which the certificate
  will be issued.
* `--key-file`: Specifies the keystore file that contains the private key that
  will be used to issue the certificate (should be owned by a trusted CA).
* `--config`: Specifies the configuration file to be used.
 In it will be contained the CA's information and optionally the key-file.

### `sign` command
#### Description
The sign command is used for signing a file by creating a .sig file that
depends on the content of the signed file and that uses the private key
specified to sign.

#### Parameters
* `--file`: Specifies the file to be signed.
* `--key-file`: Specifies the keystore file of the private key to be used for
  signing.
* `--config`: Specifies the configuration file to be used.

### `check-sig` command
#### Description
The `check-sig` command is used for checking the signature of a file.
It checks whether a given Ethereum's blockchain address signed a file as well
as if that address contains a valid certificate. If both are true, the
signature of the file is considered valid.

#### Parameters
* `--file`: Specifies the file that should have its signature checked.
* `--sig-file`: Specifies the signature file that should be checked. If not
  specified, defaults to the file's name with the .sig extension.
* `--config`: Specifies the configuration file.
 This is used to supply the CAs' addresses that are trusted.

### `get-cert` command
#### Description
The `get-cert` command is used for retrieving the certificate data and its
status from an address on the blockchain.
The status and data of the certificate are retrieved by analyzing all
transactions that came from trusted CAs' addresses to the specified address, in
chronological order.

#### Parameters
* `--address`: Specifies the address from which to retrieve the certificate.
* `--config`: Specifies the configuration file.
This is used to supply the CAs' addresses that are trusted.

### `revoke-cert` command
#### Description
The `revoke-cert` command is used to revoke a certificate that was issued on an
address of the blockchain.
This is done by creating a new transaction to that address with the operation
code for revocation.

#### Parameters
* `--address`: Specifies the address on the blockchain which will have its
  certificate revoken.
* `--key-file`: Specifies the keystore file that contains the private key that
  will be used to sign the transaction (should be owned by a trusted CA).
* `--config`: Specifies the configuration file. Can be used for supplying the
  keystore file.

### `gen-keys` command
#### Description
The `gen-keys` command is used to generate a cryptographic key pair (private
and public keys), and to generate an address on Ethereum's blockchain, which is
derived from the public key.
The private key is stored on a keystore file, protected by a password.

#### Parameters
* `--output-file`: Specifies the keystore file in which to save the private
  key.

### Configuration file
Besides the sub-commands, the program also uses a configuration file to supply
additional information that couldn't be easily passed through parameters.
This file is structured with sections, and values for each of the sections.

The `CA` section contains information about the CA to be used on the
certificates, the fields are the same as a default X.509 digital certificate,
which are `Country`, `State`, `Organization`, `OrganizationUnit` and
`CommonName`.

The `ETC` section contains additional important information, namely
`KeystoreFile` for specifying the keystore file name and `caAddresses` for
specifying the addresses of the trusted CAs, which will be the only ones
considered when evaluating the validity of a certificate in an address (that
is, only transactions that came from those addresses will be counted).

#### Sample configuration file
```
[CA]
Country = Brazil
State = Sao Paulo
Organization = Foo
OrganizationUnit = Foobar
CommonName = FooCA

[ETC]
KeystoreFile = keys/ca.json
caAddresses = 0xf513c49ee2a9102a6770778acc67e7f9a2a12af9
```

## Author

The author of this is program is Nícolas F. R. A. Prado ([nfraprado](https://github.com/nfraprado)).
