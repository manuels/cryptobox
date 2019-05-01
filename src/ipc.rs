use std::io::Cursor;
use std::io::Read;

use bytes::BytesMut;
use bytes::Buf;
use bytes::BufMut;
use bytes::IntoBuf;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::Nonce;
use sodiumoxide::crypto::box_::PublicKey;

use super::server::SecretKeyHandle;

pub trait IPCIn: Read+Buf + Sized {
    fn get_sized_vec(&mut self) -> Vec<u8> {
        let len = self.get_u64_be() as usize;
        let mut m = vec![0; len];
        self.read_exact(&mut m).unwrap();
        m
    }

    fn get_nonce(&mut self) -> Nonce {
        let mut n = vec![0u8; box_::NONCEBYTES];
        self.read_exact(&mut n[..]).unwrap();
        Nonce::from_slice(&n[..]).unwrap()
    }

    fn get_public_key(&mut self) -> PublicKey {
        let mut pk = vec![0u8; box_::PUBLICKEYBYTES];
        self.read_exact(&mut pk[..]).unwrap();
        PublicKey::from_slice(&pk[..]).unwrap()
    }

    fn get_secret_key_handle(&mut self) -> SecretKeyHandle {
        self.get_public_key() as SecretKeyHandle
    }
}

pub trait IPCOut: BufMut + Sized {
    fn put_sized_slice<T:AsRef<[u8]> + IntoBuf>(&mut self, slice: T) {
        self.put_u64_be(slice.as_ref().len() as _);
        self.put(slice);
    }
}

impl<T: AsRef<[u8]>> IPCIn for Cursor<T> {}
impl IPCOut for BytesMut {}

