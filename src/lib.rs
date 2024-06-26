//! # File Encryption
//! 
//! This crate provides a simple API to encrypt and decrypt files and directories using the AES-256-GCM algorithm.
//! 
//! ## Usage
//! 
//! Add this to your `Cargo.toml`:
//! 
//! ```toml
//! [dependencies]
//! filecipher = "1.0.0"
//! ```
//! 
//! or execute the following command:
//! 
//! ```sh
//! cargo add filecipher
//! ```
//! 
//! ## Features
//! 
//! - `dev`: Disables password prompt by using a default password and enables logging using `log` as well as benchmarking for encryption and decryption using `std::time`.
//! - `parallel`: Enables parallel processing for encrypting and decrypting files using the `rayon` crate and a fast memory pool.
//! 
//! ## Example
//! 
//! This is the most basic example of how to encrypt and decrypt a directory/file.
//! It is highly discouraged to hardcode the password in the source code.
//! 
//! ```no_run
//! use filecipher::*;
//! 
//! fn main() {
//!     let pass = "password";
//!     let key = hash_password(pass);
//! 
//!     let file = "path/to/file";
//!     encrypt_file(&file, &key).unwrap();
//!     decrypt_file(&file, &key).unwrap();
//! 
//!     let directory = "path/to/directory";
//!     encrypt_directory(&directory, &key).unwrap();
//!     decrypt_directory(&directory, &key).unwrap();
//! }
//! ```
//! 
//! ## License
//! 
//! Licensed under the MIT license.

use aead::{
    generic_array::GenericArray,
    Aead,
    AeadCore,
    KeyInit,
    OsRng,
};
use aes_gcm::Aes256Gcm;
use cipher::Unsigned;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use std::io::{self, Read, Write};
#[cfg(feature = "parallel")]
use std::sync::Arc;
#[cfg(feature = "parallel")]
use rayon::iter::{ParallelIterator, IntoParallelRefIterator};
#[cfg(feature = "dev")]
use std::time::Instant;
#[cfg(feature = "dev")]
use log::info;

mod aes_gcm;
#[cfg(feature = "parallel")]
mod memory_pool;
#[cfg(feature = "parallel")]
use memory_pool::MemoryPool;

#[cfg(not(feature = "parallel"))]
const BLOCK_SIZE: usize = 1 << 31; // 2 GiB

// POOL_SIZE must be greater than BLOCK_SIZE+tag_size (usually 16 bytes)
#[cfg(feature = "parallel")]
const POOL_SIZE: usize = 1 << 31; // 2 GiB
#[cfg(feature = "parallel")]
const BLOCK_SIZE: usize = POOL_SIZE >> 8; // 8 MiB

const EXTENSION : &str = "enc";


/// Hashes a password using the SHA-256 algorithm.
/// 
/// # Arguments
/// 
/// * `password` - A string slice that holds the password.
/// 
/// # Returns
/// 
/// A fixed-size array of 32 bytes that represents the hashed password.
/// 
/// # Example
/// 
/// ```
/// use filecipher::hash_password;
/// 
/// let password = "password";
/// let key = hash_password(password);
/// ```
pub fn hash_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.finalize().into()
}

fn encrypt_file_internal(input_file: &PathBuf, output_file: &PathBuf, key: &[u8], buffer: &mut [u8]) -> io::Result<()> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    let mut input_file = fs::File::open(input_file)?;
    let mut output_file = fs::File::create(output_file)?;

    output_file.write_all(&nonce)?;

    loop {
        let bytes_read = input_file.read(buffer)?;
        if bytes_read == 0 {
            break;
        }
        let ciphertext = cipher.encrypt(&nonce, &buffer[..bytes_read])
            .expect("encryption failure!");
        output_file.write_all(&ciphertext)?;
    }

    Ok(())
}

fn decrypt_file_internal(input_file: &PathBuf, output_file: &PathBuf, key: &[u8], buffer: &mut [u8]) -> io::Result<()> {    
    let cipher = Aes256Gcm::new(key.into());

    let mut input_file = fs::File::open(input_file)?;
    let mut output_file = fs::File::create(output_file)?;

    let mut nonce = [0u8; 12];
    input_file.read_exact(&mut nonce)?;
    let nonce = GenericArray::from_slice(&nonce);
    
    loop {
        let bytes_read = input_file.read(buffer)?;
        if bytes_read == 0 {
            break;
        }
        let plaintext = cipher.decrypt(&nonce, &buffer[..bytes_read])
            .expect("Decryption failure! Please check password or file integrity.");
        output_file.write_all(&plaintext)?;
    }

    Ok(())
}

#[cfg(feature = "parallel")]
fn encrypt_file_par(input_file: &PathBuf, output_file: &PathBuf, key: &[u8], mem_pool: Arc<MemoryPool<u8>>) -> io::Result<()> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    let mut input_file = fs::File::open(input_file)?;
    let mut output_file = fs::File::create(output_file)?;

    output_file.write_all(&nonce)?;
    
    // Warning: BLOCK_SIZE must be exactly the same as when decrypting the file.
    let file_size = input_file.metadata()?.len() as usize;
    let buffer = mem_pool.allocate_blocking(file_size.min(BLOCK_SIZE) as usize);

    loop {
        let bytes_read = input_file.read(buffer)?;
        if bytes_read == 0 {
            break;
        }
        let ciphertext = cipher.encrypt(&nonce, &buffer[..bytes_read])
            .expect("encryption failure!");
        output_file.write_all(&ciphertext)?;
    }

    mem_pool.deallocate(buffer);

    Ok(())
}

#[cfg(feature = "parallel")]
fn decrypt_file_par(input_file: &PathBuf, output_file: &PathBuf, key: &[u8], mem_pool: Arc<MemoryPool<u8>>) -> io::Result<()> {    
    let cipher = Aes256Gcm::new(key.into());

    let mut input_file = fs::File::open(input_file)?;
    let mut output_file = fs::File::create(output_file)?;

    let mut nonce = [0u8; 12];
    input_file.read_exact(&mut nonce)?;
    let nonce = GenericArray::from_slice(&nonce);

    // Warning: BLOCK_SIZE must be exactly the same as when encrypting the file.
    let file_size = input_file.metadata()?.len() as usize;
    let tag_size: usize = <Aes256Gcm as AeadCore>::TagSize::to_usize();
    let buffer = mem_pool.allocate_blocking(file_size.min(BLOCK_SIZE+tag_size) as usize);
    
    loop {
        let bytes_read = input_file.read(buffer)?;
        if bytes_read == 0 {
            break;
        }
        let plaintext = cipher.decrypt(&nonce, &buffer[..bytes_read])
            .expect("decryption failure!");
        output_file.write_all(&plaintext)?;
    }

    mem_pool.deallocate(buffer);

    Ok(())
}

/// Encrypts all files in a directory using the AES-256-GCM algorithm.
/// 
/// # Arguments
/// 
/// * `directory` - A string slice that holds the path to the directory.
/// * `key` - A fixed-size array of 32 bytes that represents the hashed password.
/// 
/// # Returns
/// 
/// An `io::Result` that indicates whether the operation was successful.
/// 
/// # Note
/// 
/// This function will skip files that have the `.enc` extension.
/// 
/// ## Example
/// 
/// ```no_run
/// use filecipher::*;
/// 
/// fn main() {
///     let directory = "path/to/directory";
///     let pass = "password";
///     let key = hash_password(pass);
/// 
///     encrypt_directory(&directory, &key).unwrap();
/// }
/// ```
pub fn encrypt_directory(directory: &str, key: &[u8]) -> io::Result<()> {
    let entries: Vec<PathBuf> = fs::read_dir(directory)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();

    #[cfg(feature = "dev")]
    let start = Instant::now();

    #[cfg(not(feature = "parallel"))]
    {
        let mut buffer = Vec::with_capacity(BLOCK_SIZE);
        assert!(buffer.capacity() >= BLOCK_SIZE, "Buffer size is smaller than BLOCK_SIZE");
        unsafe { buffer.set_len(BLOCK_SIZE) };

        for entry in entries {            
            if entry.is_file() {
                if let Some(ext) = entry.extension() {
                    if ext == EXTENSION {
                        continue;
                    }
                }
                let new_extension = format!("{}.{}", entry.extension().unwrap_or_default().to_str().unwrap_or_default(), EXTENSION);
                let output_file = entry.with_extension(new_extension);

                #[cfg(feature = "dev")]
                info!("Encrypting file {}. ", entry.display());
                encrypt_file_internal(&entry, &output_file, key, &mut buffer)?;
                #[cfg(feature = "dev")]
                info!("File {} encrypted.", entry.display());

                fs::remove_file(&entry)?;
            }
            if entry.is_dir() {
                encrypt_directory(entry.to_str().unwrap_or_default(), key)?;
            }
        }
    }

    // TODO: Better parallel processing
    #[cfg(feature = "parallel")]
    {
        let mem_pool = Arc::new(memory_pool::MemoryPool::new(POOL_SIZE));

        entries.par_iter().for_each(|entry| {
            if entry.is_file() {
                if let Some(ext) = entry.extension() {
                    if ext == EXTENSION {
                        return;
                    }
                }
                let new_extension = format!("{}.{}", entry.extension().unwrap_or_default().to_str().unwrap_or_default(), EXTENSION);
                let output_file = entry.with_extension(new_extension);

                #[cfg(feature = "dev")]
                info!("Encrypting file {}. ", entry.display());
                encrypt_file_par(&entry, &output_file, key, mem_pool.clone()).unwrap();
                #[cfg(feature = "dev")]
                info!("File {} encrypted.", entry.display());

                fs::remove_file(&entry).unwrap();
            }
            if entry.is_dir() {
                encrypt_directory(entry.to_str().unwrap_or_default(), key).unwrap();
            }
        });
    }

    #[cfg(feature = "dev")]
    {
        let duration = start.elapsed();
        info!("Time needed to encrypt {}: {:?}", directory, duration);
    }

    Ok(())
}

/// Decrypts all files in a directory using the AES-256-GCM algorithm.
/// 
/// # Arguments
/// 
/// * `directory` - A string slice that holds the path to the directory.
/// * `key` - A fixed-size array of 32 bytes that represents the hashed password.
/// 
/// # Returns
/// 
/// An `io::Result` that indicates whether the operation was successful.
/// 
/// # Note
/// 
/// This function will skip files that do not have the `.enc` extension.
/// 
/// ## Example
/// 
/// ```no_run
/// use filecipher::*;
/// 
/// fn main() {
///     let directory = "path/to/directory";
///     let pass = "password";
///     let key = hash_password(pass);
/// 
///     decrypt_directory(&directory, &key).unwrap();
/// }
/// ```
pub fn decrypt_directory(directory: &str, key: &[u8]) -> io::Result<()> {
    let entries: Vec<PathBuf> = fs::read_dir(directory)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();

    #[cfg(feature = "dev")]
    let start = Instant::now();

    #[cfg(not(feature = "parallel"))]
    {
        let tag_size: usize = <Aes256Gcm as AeadCore>::TagSize::to_usize();
        let mut buffer = Vec::with_capacity(BLOCK_SIZE+tag_size);
        assert!(buffer.capacity() >= BLOCK_SIZE+tag_size, "Buffer size is smaller than BLOCK_SIZE");
        unsafe { buffer.set_len(BLOCK_SIZE+tag_size) };

        for entry in entries {            
            if entry.is_file() {
                if let Some(ext) = entry.extension() {
                    if ext != EXTENSION {
                        continue;
                    }
                }
                let output_file = entry.with_extension("");

                #[cfg(feature = "dev")]
                info!("Decrypting file {}. ", entry.display());
                decrypt_file_internal(&entry, &output_file, key, &mut buffer)?;
                #[cfg(feature = "dev")]
                info!("File {} decrypted.", entry.display());

                fs::remove_file(&entry)?;
            }
            if entry.is_dir() {
                decrypt_directory(entry.to_str().unwrap_or_default(), key)?;
            }
        }
    }

    // TODO: Better parallel processing
    #[cfg(feature = "parallel")]
    {
        let mem_pool = Arc::new(memory_pool::MemoryPool::new(POOL_SIZE));

        entries.par_iter().for_each(|entry| {            
            if entry.is_file() {
                if let Some(ext) = entry.extension() {
                    if ext != EXTENSION {
                        return;
                    }
                }
                let output_file = entry.with_extension("");

                #[cfg(feature = "dev")]
                info!("Decrypting file {}. ", entry.display());
                decrypt_file_par(&entry, &output_file, key, mem_pool.clone()).unwrap();
                #[cfg(feature = "dev")]
                info!("File {} decrypted.", entry.display());

                fs::remove_file(&entry).unwrap();
            }
            if entry.is_dir() {
                decrypt_directory(entry.to_str().unwrap_or_default(), key).unwrap();
            }
        });
    }
    
    #[cfg(feature = "dev")]
    {
        let duration = start.elapsed();
        info!("Time needed to decrypt {}: {:?}", directory, duration);
    }

    Ok(())
}

/// Encrypts a file using the AES-256-GCM algorithm.
/// 
/// # Arguments
/// 
/// * `file` - A string slice that holds the path to the file.
/// * `key` - A fixed-size array of 32 bytes that represents the hashed password.
/// 
/// # Returns
/// 
/// An `io::Result` that indicates whether the operation was successful.
/// 
/// # Note
/// 
/// This function will skip files that have the `.enc` extension.
/// 
/// ## Example
/// 
/// ```no_run
/// use filecipher::*;
/// 
/// fn main() {
///     let file = "path/to/file";
///     let pass = "password";
///     let key = hash_password(pass);
/// 
///     encrypt_file(&file, &key).unwrap();
/// }
/// ```
pub fn encrypt_file(file: &str, key: &[u8]) -> io::Result<()> {
    #[cfg(feature = "dev")]
    let start = Instant::now();

    let mut buffer = vec![0u8; BLOCK_SIZE];
    assert!(buffer.len() >= BLOCK_SIZE, "Buffer size is not equal to BLOCK_SIZE");

    let input_file = PathBuf::from(file);
    let file_metadata = input_file.metadata()?;
    
    if file_metadata.is_file() {
        if let Some(ext) = input_file.extension() {
            if ext == EXTENSION {
                return Ok(());
            }
        }
        let new_extension = format!("{}.{}", input_file.extension().unwrap_or_default().to_str().unwrap_or_default(), EXTENSION);
        let output_file = input_file.with_extension(new_extension);

        encrypt_file_internal(&input_file, &output_file, key, &mut buffer)?;

        fs::remove_file(&input_file)?;
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid file."));
    }

    #[cfg(feature = "dev")]
    {
        let duration = start.elapsed();
        info!("Time elapsed: {:?}", duration);
    }

    Ok(())
}

/// Decrypts a file using the AES-256-GCM algorithm.
/// 
/// # Arguments
/// 
/// * `file` - A string slice that holds the path to the file.
/// * `key` - A fixed-size array of 32 bytes that represents the hashed password.
/// 
/// # Returns
/// 
/// An `io::Result` that indicates whether the operation was successful.
/// 
/// # Note
/// 
/// This function will skip files that do not have the `.enc` extension.
/// 
/// ## Example
/// 
/// ```no_run
/// use filecipher::*;
/// 
/// fn main() {
///     let file = "path/to/file";
///     let pass = "password";
///     let key = hash_password(pass);
/// 
///     decrypt_file(&file, &key).unwrap();
/// }
/// ```
pub fn decrypt_file(file: &str, key: &[u8]) -> io::Result<()> {
    #[cfg(feature = "dev")]
    let start = Instant::now();

    let tag_size: usize = <Aes256Gcm as AeadCore>::TagSize::to_usize();
    let mut buffer = vec![0u8; BLOCK_SIZE+tag_size];
    assert!(buffer.len() >= BLOCK_SIZE, "Buffer size is not equal to BLOCK_SIZE");

    let input_file = PathBuf::from(file);
    let file_metadata = input_file.metadata()?;
    
    if file_metadata.is_file() {
        if let Some(ext) = input_file.extension() {
            if ext != EXTENSION {
                return Ok(());
            }
        }
        let output_file = input_file.with_extension("");

        decrypt_file_internal(&input_file, &output_file, key, &mut buffer)?;

        fs::remove_file(&input_file)?;
    } else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid file."));
    }

    #[cfg(feature = "dev")]
    {
        let duration = start.elapsed();
        info!("Time elapsed: {:?}", duration);
    }

    Ok(())
}
