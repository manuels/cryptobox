use std::io::Cursor;
use std::os::unix::io::RawFd;
use std::os::unix::io::FromRawFd;
use std::collections::HashMap;

use bytes::buf::Buf;
use bytes::buf::BufMut;
use bytes::BytesMut;

use sodiumoxide;
use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::PublicKey;
use sodiumoxide::crypto::box_::SecretKey;

use super::ipc::{IPCIn, IPCOut};
use super::seccomp::run_seccomp;

pub type SecretKeyHandle = PublicKey;

pub const CMD_GEN_KEYPAIR: i8 = 1;
pub const CMD_SEAL: i8        = 2;
pub const CMD_OPEN: i8        = 3;

pub fn run_server(ipc_fd: RawFd) -> isize {
    assert_eq!(Ok(()), sodiumoxide::init());

    run_seccomp(ipc_fd);

    let sock = unsafe {
       std::os::unix::net::UnixDatagram::from_raw_fd(ipc_fd)
    };

    let mut keys = HashMap::new(); // TODO: hashmap, really?

    let mut buf = [0; 8 * 1024];
    loop {
        match sock.recv(&mut buf) {
            Ok(n) if n > 0 => {
                let mut req = Cursor::new(&buf[..n]);
                let cmd = req.get_i8();

                let resp = match cmd {
                    n if n == CMD_GEN_KEYPAIR => gen_keypair(&mut keys),
                    n if n == CMD_SEAL => seal(req, &mut keys),
                    n if n == CMD_OPEN => open(req, &mut keys),
                    n => {println!("cmd = {}", n); unimplemented!() },
                };

                let resp = &resp.freeze();
                let len = resp.len();
                let n = sock.send(resp).unwrap();
                assert_eq!(n, len);
            },
            Ok(_) => eprintln!("msg too short"),
            Err(err) => println!("err {:?}", err),
        }
    }
}

fn gen_keypair(keys: &mut HashMap<SecretKeyHandle, SecretKey>) -> BytesMut {
    let (pk, sbox) = box_::gen_keypair();

    let mut resp = BytesMut::with_capacity(box_::PUBLICKEYBYTES);
    resp.put(&pk[..]);

    keys.insert(pk, sbox);

    resp
}

fn seal(mut req: Cursor<&[u8]>, keys: &mut HashMap<SecretKeyHandle, SecretKey>) -> BytesMut {
    let m = req.get_sized_vec();
    let n = req.get_nonce();
    let pk = req.get_public_key();
    let skh = req.get_secret_key_handle();
    
    let sk = keys.get(&skh).unwrap();

    let c = box_::seal(&m, &n, &pk, &sk);

    // TODO: overflow!
    let mut resp = BytesMut::with_capacity(8 + c.len());
    resp.put_sized_slice(&c);

    resp
}

fn open(mut req: Cursor<&[u8]>, keys: &mut HashMap<SecretKeyHandle, SecretKey>) -> BytesMut {
    let c = req.get_sized_vec();
    let n = req.get_nonce();
    let pk = req.get_public_key();
    let skh = req.get_secret_key_handle();
    
    let sk = keys.get(&skh).unwrap();

    let resp = if let Ok(m) = box_::open(&c, &n, &pk, &sk) {
        // TODO: overflow!
        let mut resp = BytesMut::with_capacity(1 + 8 + m.len());
        resp.put_i8(0);
        resp.put_sized_slice(&m);
        resp
    } else {
        let mut resp = BytesMut::with_capacity(1);
        resp.put_i8(-1);
        resp
    };

    resp
}
