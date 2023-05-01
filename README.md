# Rustpass

Rustpass is a simple password generator and encryption tool written in Rust. It uses AES encryption to securely store passwords.

## Usage
To use Rustpass, simply run the program using cargo run. The program will generate a random password, encrypt it using AES-256 encryption, and store it in a file called password.txt. The encryption key is also generated randomly and stored in memory.

To decrypt the password, run the program again and it will read the encrypted password from the password.txt file and decrypt it using the encryption key that was stored in memory.

## Dependencies
rand (0.8.5)
rust-crypto (0.2.36)