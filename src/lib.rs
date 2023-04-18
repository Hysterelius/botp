//! Documentation for botp, a Blake3 implementation of hotp. Which is more secure
//! as it uses a 11 digit number compared to the 6 digit number of the usual specification.
//!
//! # Example
//! ```
//! use std::time::UNIX_EPOCH;
//! let key = generate_secret_key();
//! let code = botp(
//!     get_counter(30, UNIX_EPOCH),
//!     key
//! );
//! ```
//!

use blake3::keyed_hash;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use std::time::SystemTime;

pub enum Error {
    TimeError,
    RandomBytesError,
}

trait WrapIndex {
    type Item;
    fn wrapped_index(&self, index: usize) -> &Self::Item;
}

impl<T> WrapIndex for [T] {
    type Item = T;

    /// The wrapped index of any array, allowing for calls that would normally be out of bounds to be within bounds
    ///
    /// # Example
    /// ```
    /// let x = [1, 2, 3, 4];
    /// x[5] // Normal use, throws an error
    /// x.wrapped_index(5) // Wrapped use, would return `1` (the index % size_of_array)
    fn wrapped_index(&self, index: usize) -> &Self::Item {
        let wrapped_index = index % self.len();
        &self[wrapped_index]
    }
}

pub fn botp(counter: u64, secret: [u8; 32]) -> u64 {
    let counter_ne: [u8; 8] = counter.to_be_bytes();

    let hash = keyed_hash(&secret, &counter_ne);
    let hash_bytes: &[u8; 32] = hash.as_bytes();

    truncate(&hash_bytes)
}

fn truncate(hash_bytes: &[u8; 32]) -> u64 {
    let offset: usize = ((hash_bytes[31]) % 28) as usize;
    println!("{:?}", offset);

    let binned_code: u64 = u64::from_be_bytes([
        (hash_bytes.wrapped_index(offset) & 0x7f),
        (hash_bytes.wrapped_index(offset + 1) & 0xff),
        (hash_bytes.wrapped_index(offset + 2) & 0xff),
        (hash_bytes.wrapped_index(offset + 3) & 0xff),
        // Next 8 bytes
        (hash_bytes.wrapped_index(offset + 4) & 0xff),
        (hash_bytes.wrapped_index(offset + 5) & 0xff),
        (hash_bytes.wrapped_index(offset + 6) & 0xff),
        (hash_bytes.wrapped_index(offset + 7) & 0xff),
    ]);
    println!("Binned code: {:?}", binned_code);

    let code = binned_code % 100_000_000_000;
    println!("Code: {:?}", code);
    code
}

pub fn get_counter(interval: u64, epoch: SystemTime) -> Result<u64, Error> {
    match SystemTime::now().duration_since(epoch) {
        Ok(t) => Ok(t.as_secs() / interval),
        Err(_) => Err(Error::TimeError),
    }
}

pub fn generate_secret_key() -> Result<[u8; 32], Error> {
    let mut rng = ChaCha20Rng::from_entropy();
    let mut secret_key = [0; 32];
    rng.try_fill_bytes(&mut secret_key)
        .map_err(|_| Error::RandomBytesError)?;
    Ok(secret_key)
}
