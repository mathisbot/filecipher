use aes::Aes256;
use aead::{self, AeadCore, AeadInPlace, Error, Key, KeyInit, KeySizeUser};
use cipher::{
    consts::{U0, U12, U16},
    generic_array::{ArrayLength, GenericArray},
    BlockCipher, BlockEncrypt, BlockSizeUser, InnerIvInit, StreamCipherCore,
};
use core::marker::PhantomData;
use ghash::{universal_hash::UniversalHash, GHash};
use subtle::ConstantTimeEq;

pub const MAX_LEN_ASSOCIATED_DATA: u64 = 1 << 36; // 64 GB
pub const MAX_LEN_PLAINTEXT: u64 = 1 << 36; // 64 GB
pub const MAX_LEN_CIPHERTEXT: u64 = MAX_LEN_PLAINTEXT + 16; // 64 GB + 16 bytes (GHASH tag)

pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;
pub type Tag<TagSize = U16> = GenericArray<u8, TagSize>;
pub trait TagSize: sealed::SealedTagSize {}

impl<T: sealed::SealedTagSize> TagSize for T {}

mod sealed {
    use aead::generic_array::ArrayLength;
    use cipher::{consts, Unsigned};

    pub trait SealedTagSize: ArrayLength<u8> + Unsigned {}
    impl SealedTagSize for consts::U16 {}
}

// AES-GCM with a 256-bit key and 96-bit nonce.
pub type Aes256Gcm = AesGcm<Aes256, U12>;

type Block = GenericArray<u8, U16>;

type Ctr64BE<Aes> = ctr::CtrCore<Aes, ctr::flavors::Ctr64BE>;

#[derive(Clone)]
pub struct AesGcm<Aes, NonceSize, TagSize = U16>
where
    TagSize: self::TagSize,
{
    cipher: Aes,
    ghash: GHash,
    nonce_size: PhantomData<NonceSize>,
    tag_size: PhantomData<TagSize>,
}

impl<Aes, NonceSize, TagSize> KeySizeUser for AesGcm<Aes, NonceSize, TagSize>
where
    Aes: KeySizeUser,
    TagSize: self::TagSize,
{
    type KeySize = Aes::KeySize;
}

impl<Aes, NonceSize, TagSize> KeyInit for AesGcm<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
    TagSize: self::TagSize,
{
    fn new(key: &Key<Self>) -> Self {
        Aes::new(key).into()
    }
}

impl<Aes, NonceSize, TagSize> From<Aes> for AesGcm<Aes, NonceSize, TagSize>
where
    Aes: BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    TagSize: self::TagSize,
{
    fn from(cipher: Aes) -> Self {
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);
        let ghash = GHash::new(&ghash_key);

        Self {
            cipher,
            ghash,
            nonce_size: PhantomData,
            tag_size: PhantomData,
        }
    }
}

impl<Aes, NonceSize, TagSize> AeadCore for AesGcm<Aes, NonceSize, TagSize>
where
    NonceSize: ArrayLength<u8>,
    TagSize: self::TagSize,
{
    type NonceSize = NonceSize;
    type TagSize = TagSize;
    type CiphertextOverhead = U0;
}

impl<Aes, NonceSize, TagSize> AeadInPlace for AesGcm<Aes, NonceSize, TagSize>
where
    Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    NonceSize: ArrayLength<u8>,
    TagSize: self::TagSize,
{
    fn encrypt_in_place_detached(&self, nonce: &Nonce<NonceSize>, associated_data: &[u8], buffer: &mut [u8]) -> Result<Tag<TagSize>, Error> {
        if buffer.len() as u64 > MAX_LEN_PLAINTEXT || associated_data.len() as u64 > MAX_LEN_ASSOCIATED_DATA {
            return Err(Error);
        }

        let (ctr, mask) = self.init_ctr(nonce);

        // TODO: Encryption and GHASH at the same time
        // https://github.com/RustCrypto/AEADs/issues/74
        ctr.apply_keystream_partial(buffer.into());

        let full_tag = self.compute_tag(mask, associated_data, buffer);

        Ok(Tag::clone_from_slice(&full_tag[..TagSize::to_usize()]))
    }

    fn decrypt_in_place_detached(&self, nonce: &Nonce<NonceSize>, associated_data: &[u8], buffer: &mut [u8], tag: &Tag<TagSize>) -> Result<(), Error> {
        if buffer.len() as u64 > MAX_LEN_CIPHERTEXT || associated_data.len() as u64 > MAX_LEN_ASSOCIATED_DATA {
            return Err(Error);
        }

        let (ctr, mask) = self.init_ctr(nonce);

        // TODO: Encryption and GHASH at the same time
        // https://github.com/RustCrypto/AEADs/issues/74
        let expected_tag = self.compute_tag(mask, associated_data, buffer);

        // Subtle allows for constant-time cryptographic comparisons
        if expected_tag[..TagSize::to_usize()].ct_eq(tag).into() {
            ctr.apply_keystream_partial(buffer.into());
            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<Aes, NonceSize, TagSize> AesGcm<Aes, NonceSize, TagSize>
where
    Aes: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    NonceSize: ArrayLength<u8>,
    TagSize: self::TagSize,
{
    fn init_ctr(&self, nonce: &Nonce<NonceSize>) -> (Ctr64BE<&Aes>, Block) {
        let j0 = if NonceSize::to_usize() == 12 {
            let mut block = ghash::Block::default();
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            block
        } else {
            let mut ghash = self.ghash.clone();
            ghash.update_padded(nonce);
            let mut block = ghash::Block::default();
            let nonce_bits = (NonceSize::to_usize() as u64) * 8;
            block[8..].copy_from_slice(&nonce_bits.to_be_bytes());
            ghash.update(&[block]);
            ghash.finalize()
        };

        let mut ctr = Ctr64BE::inner_iv_init(&self.cipher, &j0);
        let mut tag_mask = Block::default();
        ctr.write_keystream_block(&mut tag_mask);

        (ctr, tag_mask)
    }

    fn compute_tag(&self, mask: Block, associated_data: &[u8], buffer: &[u8]) -> Tag {
        let mut ghash = self.ghash.clone();
        ghash.update_padded(associated_data);
        ghash.update_padded(buffer);

        let associated_data_bits = (associated_data.len() as u64) * 8;
        let buffer_bits = (buffer.len() as u64) * 8;

        let mut block = ghash::Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        ghash.update(&[block]);

        let mut tag = ghash.finalize();
        for (a, b) in tag.as_mut_slice().iter_mut().zip(mask.as_slice()) {
            *a ^= *b;
        }

        tag
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use aead::OsRng;

    #[test]
    fn test_aes_gcm() {
        // Unsafe to use a zero key, fine for testing
        let key = [0u8; 32];
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let associated_data = b"associated data";
        let plaintext = b"plaintext";

        let cipher = Aes256Gcm::new(&key.into());
        let mut ciphertext = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(&nonce, associated_data, &mut ciphertext).unwrap();

        let mut decrypted = ciphertext.clone();
        cipher.decrypt_in_place_detached(&nonce, associated_data, &mut decrypted, &tag).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_aes_gcm_large_data() {
        // Unsafe to use a zero key, fine for testing
        let key = [0u8; 32];
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let associated_data = b"associated data";
        let plaintext = vec![0u8; 1_000_000];

        let cipher = Aes256Gcm::new(&key.into());
        let mut ciphertext = plaintext.clone();
        let tag = cipher.encrypt_in_place_detached(&nonce, associated_data, &mut ciphertext).unwrap();

        let mut decrypted = ciphertext.clone();
        cipher.decrypt_in_place_detached(&nonce, associated_data, &mut decrypted, &tag).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_gcm_empty_data() {
        // Unsafe to use a zero key, fine for testing
        let key = [0u8; 32];
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let associated_data = b"associated data";
        let plaintext = vec![];

        let cipher = Aes256Gcm::new(&key.into());
        let mut ciphertext = plaintext.clone();
        let tag = cipher.encrypt_in_place_detached(&nonce, associated_data, &mut ciphertext).unwrap();

        let mut decrypted = ciphertext.clone();
        cipher.decrypt_in_place_detached(&nonce, associated_data, &mut decrypted, &tag).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
