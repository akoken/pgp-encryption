# PGP Encryption Tool

## Description
This is a Rust-based command-line tool that encrypts files using PGP (Pretty Good Privacy). It allows users to encrypt files from a specified input directory and save the encrypted versions to an output directory. The tool leverages the `sequoia-openpgp` crate for encryption and supports public key-based encryption.

## Features
- Encrypts all files in a given input folder
- Outputs encrypted files to a specified directory
- Supports public key encryption using the `sequoia-openpgp` crate
- Maintains relative directory structure in the output folder

## Installation
Clone the repository and navigate to the project directory:
```sh
git clone https://github.com/akoken/pgp-encryption.git
cd pgp-encryption
```

Then, build the project:
```sh
cargo build --release
```

## Usage
Run the tool using the following command:
```sh
./target/release/pgp-encryption -f <input_folder> -o <output_folder> -k <public_key_file>
```

### Arguments:
- `-f, --folder` : Input folder containing files to encrypt
- `-o, --output` : Output folder where encrypted files will be stored
- `-k, --key`    : Path to the public key file used for encryption

### Example:
```sh
./target/release/pgp-encryption -f ./documents -o ./encrypted -k public-key.asc
```

## Build from Source
To compile the project manually, run:
```sh
cargo build --release
```
This will create an optimized binary in the `target/release` directory.

## Dependencies
The project relies on the following Rust crates:
- `sequoia-openpgp` for PGP encryption
- `walkdir` for directory traversal
- `clap` for command-line argument parsing

## Error Handling
If an error occurs, the program will output an error message and return an appropriate exit code:
- `1` : Invalid input
- `2` : Public key error
- `3` : Encryption failure
- `4` : I/O error
