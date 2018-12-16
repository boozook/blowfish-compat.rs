extern crate blowfish_compat;
use blowfish_compat::*;

use std::io::Cursor;
use std::io::Read;
use std::fs::File;

include!("paths.rs.inc");


#[test]
fn decrypt_streammed() {
	test_decrypt_stream(FILE0, FILE0_KEY, FILE0_DE).unwrap();
	test_decrypt_stream(FILE1, FILE1_KEY, FILE1_DE).unwrap();
}

#[test]
fn decrypt_inplace() {
	test_decrypt_inplace(FILE0, FILE0_KEY, FILE0_DE).unwrap();
	test_decrypt_inplace(FILE1, FILE1_KEY, FILE1_DE).unwrap();
}


fn test_decrypt_inplace(file_path: &str, key: &[u8], expected_file_path: &str) -> Result<(), std::io::Error> {
	let mut buf = Vec::new();
	let mut f = File::open(file_path)?;

	f.read_to_end(&mut buf)?;
	add_padding(&mut buf);

	crypt_util::decrypt(&mut buf, key).unwrap();

	drain_tail(&mut buf);

	cmp_slice_file(&buf, expected_file_path)
}


fn test_decrypt_stream(file_path: &str, key: &[u8], expected_file_path: &str) -> Result<(), std::io::Error> {
	let mut inp = File::open(file_path)?;
	let mut out = Cursor::new(Vec::new());

	crypt_util::decrypt_stream(&mut inp, key, &mut out)?;

	let result = out.into_inner();
	cmp_slice_file(&result, expected_file_path)
}


#[inline]
fn cmp_slice_file(buf: &[u8], file_path: &str) -> Result<(), std::io::Error> {
	let mut expected = Vec::new();
	{
		let mut f = File::open(file_path)?;
		f.read_to_end(&mut expected)?;
	}
	assert_eq!(expected.len(), buf.len());
	assert_eq!(expected, buf);
	Ok(())
}


/// zero-padding
static END_TAIL: [u8; 3] = [0; 3];

/// Drains zero-padding and the last byte in the encrypted file is the amount of bytes
/// from the last decrypted block which should be actually read.
#[inline]
fn drain_tail(buf: &mut Vec<u8>) {
	if &buf[(buf.len() - 11)..(buf.len() - 8)] == &END_TAIL {
		buf.drain((buf.len() - 8)..);
	}
}


#[inline]
pub fn add_padding(buf: &mut Vec<u8>) {
	static ZERO_BLOCK: [u8; BLOCK_SIZE] = [0_u8; BLOCK_SIZE];
	let diff = buf.len() % BLOCK_SIZE;
	if diff > 0 {
		buf.extend(&ZERO_BLOCK[..(BLOCK_SIZE - diff)]);
	}
}


mod crypt_util {
	use super::*;
	use std::io::Write;
	use blowfish::block_cipher_trait::generic_array::GenericArray;
	use blowfish::block_cipher_trait::{BlockCipher, InvalidKeyLength};

	pub fn decrypt(buf: &mut [u8], key: &[u8]) -> Result<(), InvalidKeyLength> {
		// check size & padding:
		assert!(buf.len() % BLOCK_SIZE == 0);

		let cypher = BlowfishCompat::new_varkey(key)?;
		for chunk in buf.chunks_mut(BLOCK_SIZE) {
			cypher.decrypt_block(GenericArray::from_mut_slice(chunk));
		}
		Ok(())
	}

	pub fn decrypt_stream<R: Read>(reader: &mut R, key: &[u8], out: &mut Write) -> Result<(), std::io::Error> {
		let cypher: BlowfishCompat = BlockCipher::new_varkey(key).unwrap();
		let mut buf = [0; BLOCK_SIZE];
		loop {
			match reader.read_exact(&mut buf) {
				Ok(_) => {
					cypher.decrypt_block(GenericArray::from_mut_slice(&mut buf));
					out.write_all(&buf)?;
				},
				Err(_err) => break,
			}
		}
		out.flush()
	}

}
