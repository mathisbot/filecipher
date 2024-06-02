# File Cipher

This crate provides a Rust API that uses AES-256-GCM to encrypt/decrypt files/directories.

## Features

- `dev`: Disables password prompt by using a default password and enables benchmarking for encryption and decryption using `std::time`.
- `parallel`: Enables parallel processing for encrypting and decrypting directories using the `rayon` crate and a fast memory pool.

## Installation

1. Clone the repository:

    ```shell
    git clone https://github.com/mathisbot/filecipher.git
    ```

2. Navigate to the project directory:

    ```shell
    cd filecipher
    ```

3. Build the project:

    ```shell
    cargo build --release
    ```

## Usage

For more information, please refer to the documentation :

```shell
cargo doc --open
```

### Basic example

```rust
use filecipher::*;

fn main() {
    let pass = "password";
    let key = hash_password(pass);

    let file = "path/to/file";
    encrypt_file(&file, &key).unwrap();
    decrypt_file(&file, &key).unwrap();

    let directory = "path/to/directory";
    encrypt_directory(&directory, &key).unwrap();
    decrypt_directory(&directory, &key).unwrap();
}
```
