extern crate crypto;
extern crate rand;

use crate::rand::RngCore;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer, symmetriccipher};
use rand::rngs::OsRng;
use rand::Rng;
use std::fs::File;
use std::io::Write;

fn generate_password(length: usize) -> String {
    let mut password = String::new();
    let mut rng = rand::thread_rng();
    let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?";

    for _ in 0..length {
        // Generates a random number that we'll use as an index
        let idx = rng.gen_range(0..chars.len());
        // Extracts a char from a string with the index we randomly choose
        let ch = chars[idx..idx + 1].chars().next().unwrap();
        password.push(ch);
    }
    password
}

fn encrypt_password(
    password: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor = aes::cbc_encryptor(
        aes::KeySize::KeySize256,
        key,
        &[0; 16],
        blockmodes::PkcsPadding,
    );
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(password);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

        // "write_buffer.take_read_buffer().take_remaining()" means:
        // from the writable buffer, create a new readable buffer which
        // contains all data that has been written, and then access all
        // of that data as a slice.
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    Ok(final_result)
}

fn decrypt_password(
    encrypted_password: &[u8],
    key: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        key,
        &[0; 16],
        blockmodes::PkcsPadding,
    );
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_password);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

fn main() {
    let password = generate_password(16);
    let mut key: [u8; 32] = [0; 32];
    OsRng.fill_bytes(&mut key);
    let encrypted_password = encrypt_password(password.as_bytes(), &key);

    // Creates a file "password.txt" and writes the generated encrypted password
    let mut file = File::create("password.txt").expect("The file couldn't be created");
    file.write_all(&encrypted_password.clone().ok().unwrap())
        .expect("Couldn't write in the file");

    let decrypted_password = decrypt_password(&encrypted_password.clone().ok().unwrap(), &key);

    println!("Generated password: {}", password);
    println!("Encrypted password: {:?}", encrypted_password.ok().unwrap());
    println!(
        "Decrypted password: {}",
        std::str::from_utf8(&decrypted_password.unwrap())
            .unwrap()
            .to_string()
    );
}
