Simple impl. of [Blowfish-compat][] cipher as wrapper of wrapper of [blowfish crate][]::Blowfish.

### Example

```toml
# Cargo.toml
[dependencies]
blowfish-compat = "0.1.0"

# or with feachure "use bswap"
[dependencies.blowfish-compat]
features = ["bswap"]
version = "0.1.0"
```

```rust
use std::fs::File;
use std::io::{Cursor, Read, Write, Error};

extern crate blowfish_compat;
use blowfish_compat::{BlowfishCompat, BLOCK_SIZE};
use blowfish_compat::block_cipher_trait::generic_array::GenericArray;
use blowfish_compat::block_cipher_trait::{BlockCipher, InvalidKeyLength};


fn test_decrypt_stream(file_path: &str, key: &[u8]) -> Result<(), Error> {
	let mut inp = File::open(file_path)?;
	let mut out = Cursor::new(Vec::new());

	decrypt_stream(&mut inp, key, &mut out)?;
	let result = out.into_inner();

	// use result...

	Ok(())
}

fn decrypt_stream<R: Read>(reader: &mut R, key: &[u8], out: &mut Write) -> Result<(), Error> {
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
```



[blowfish crate]: https://crates.io/crates/blowfish
[Blowfish-compat]: https://stackoverflow.com/a/11423057/829264
