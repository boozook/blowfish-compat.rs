#![no_std]
//! Wrapper under the blowfish algorithm
//! Implements compatibility with
//! - https://stackoverflow.com/a/11423057/829264
//! - https://github.com/winlibs/libmcrypt/blob/master/modules/algorithms/blowfish-compat.c
//!
//! Supports `#![no_std]`.
//! Optionally supports `bswap` crate as feature.

extern crate blowfish;
pub use blowfish::*;

use blowfish::{Blowfish, BlockCipher};
use blowfish::block_cipher_trait::InvalidKeyLength;
use blowfish::block_cipher_trait::generic_array::{GenericArray, typenum::{U8, U56}};

#[cfg(feature = "bswap")]
extern crate bswap;


/// Size (length) of word
pub(crate) const WORD: usize = 4;
/// Size (length) of chunk/block
pub const BLOCK_SIZE: usize = 8;


/**
	Takes data and reverses byte order inplace to fit
	blowfish-compat format.
	```
	use blowfish_compat::reverse_words;
	let mut s = "12345678".to_owned();
	reverse_words(unsafe { s.as_bytes_mut() });
	assert_eq!(&s, "43218765");
	```
*/
#[inline]
pub fn reverse_words(buf: &mut [u8]) {
	#[cfg(target_endian = "little")]
	{
		#[cfg(feature = "bswap")]
		unsafe {
			let buf_len = buf.len();
			// chunk by chunk where size is power of WORD but not huge or "bus-err/out of mem".
			return bswap::u32::swap_memory_inplace(&mut buf[0] as *mut u8, buf_len - buf_len % WORD);
		}

		#[cfg(not(feature = "bswap"))]
		for chunk in buf.chunks_mut(WORD) {
			chunk.reverse();
		}
	}
}


// copy of the private type-alias `blowfish::Block`.
type Block = GenericArray<u8, U8>;

/// BlowfishCompat is wrapper for the `Blowfish`,
/// implements `blowfish::BlockCipher` trait.
#[derive(Clone, Copy)]
pub struct BlowfishCompat {
	inner: Blowfish,
}

impl BlockCipher for BlowfishCompat {
	type KeySize = <Blowfish as BlockCipher>::KeySize;
	type BlockSize = <Blowfish as BlockCipher>::BlockSize;
	type ParBlocks = <Blowfish as BlockCipher>::ParBlocks;

	fn new(key: &GenericArray<u8, U56>) -> Self { Self { inner: <Blowfish as BlockCipher>::new(key) } }

	fn new_varkey(key: &[u8]) -> Result<Self, InvalidKeyLength> {
		<Blowfish as BlockCipher>::new_varkey(key).map(|bf| Self { inner: bf })
	}

	#[inline]
	fn encrypt_block(&self, block: &mut Block) {
		reverse_words(block);
		self.inner.encrypt_block(block);
		reverse_words(block);
	}

	#[inline]
	fn decrypt_block(&self, block: &mut Block) {
		reverse_words(block);
		self.inner.decrypt_block(block);
		reverse_words(block);
	}
}
