use std::sync::Once;
use std::io::Cursor;
use std::os::unix::io::RawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixDatagram;

use nix;

use sodiumoxide::crypto::box_;
use sodiumoxide::crypto::box_::Nonce;
use sodiumoxide::crypto::box_::PublicKey;

use bytes::BytesMut;
use bytes::buf::Buf;
use bytes::buf::BufMut;

use super::server;
use super::ipc::IPCIn;
use super::ipc::IPCOut;

static INIT: Once = Once::new();
static mut INIT_RESULT: Option<UnixDatagram> = None;

use super::server::SecretKeyHandle;
use super::server::CMD_GEN_KEYPAIR;
use super::server::CMD_SEAL;
use super::server::CMD_OPEN;

pub fn init() -> Result<(), ()> {
    unsafe {
        INIT.call_once(|| {
            let fd = spawn_process().unwrap();
            let sock = UnixDatagram::from_raw_fd(fd);
            INIT_RESULT = Some(sock);
        });
        Ok(())
    }
}

fn setup_ipc() -> nix::Result<(RawFd, RawFd)> {
    nix::sys::socket::socketpair(
        nix::sys::socket::AddressFamily::Unix,
        nix::sys::socket::SockType::SeqPacket,
        None,
        nix::sys::socket::SockFlag::empty(),
    )
}

fn spawn_process() -> nix::Result<RawFd> {
    let (parent_fd, child_fd) = setup_ipc().unwrap();

    let func = Box::new(move || server::run_server(child_fd));
    let mut stack = [0u8; 0];
    let flags = nix::sched::CloneFlags::CLONE_UNTRACED; // TODO: Correct?
    let signal = None; // TODO: Correct?
    
    let res = nix::sched::clone(func, &mut stack, flags, signal);

    res.map(|_pid| parent_fd)
}

pub fn gen_keypair() -> (PublicKey, SecretKeyHandle) {
    let sock = unsafe { &INIT_RESULT.as_ref().unwrap() };
    let n = sock.send(&[CMD_GEN_KEYPAIR as u8]).unwrap();
    assert_eq!(n, 1);

    let mut buf = vec![0; 32];
    let n = sock.recv(&mut buf[..]).unwrap();

    let pk = PublicKey::from_slice(&buf[..n]).unwrap();
    let skh = PublicKey::from_slice(&buf[..n]).unwrap();

    (pk, skh)
}

pub fn seal(m: &[u8], n: &Nonce, pk: &PublicKey, skh: &SecretKeyHandle) -> Vec<u8> {
    let len = 1 + 8 + m.len() + box_::NONCEBYTES + box_::PUBLICKEYBYTES + box_::PUBLICKEYBYTES;
    let mut buf = BytesMut::with_capacity(len);
    buf.put_i8(CMD_SEAL);
    buf.put_sized_slice(&m[..]);
    buf.put(&n[..]);
    buf.put(&pk[..]);
    buf.put(&skh[..]);

    let sock = unsafe { &INIT_RESULT.as_ref().unwrap() };
    let n = sock.send(&buf.freeze()).unwrap();
    assert_eq!(n, len);

    let mut buf = vec![0; m.len() + 2 * 1024];
    let n = sock.recv(&mut buf[..]).unwrap();
    let mut resp = Cursor::new(&buf[..n]);

    let c = resp.get_sized_vec();
    c
}

pub fn open(c: &[u8], n: &Nonce, pk: &PublicKey, skh: &SecretKeyHandle) -> Result<Vec<u8>, ()> {
    let len = 1 + 8 + c.len() + box_::NONCEBYTES + box_::PUBLICKEYBYTES + box_::PUBLICKEYBYTES;
    let mut buf = BytesMut::with_capacity(len);
    buf.put_i8(CMD_OPEN);
    buf.put_sized_slice(&c[..]);
    buf.put(&n[..]);
    buf.put(&pk[..]);
    buf.put(&skh[..]);

    let sock = unsafe { &INIT_RESULT.as_ref().unwrap() };
    let n = sock.send(&buf.freeze()).unwrap();
    assert_eq!(n, len);

    // TODO: overflow?
    let mut buf = vec![0; c.len() + 2 * 1024];
    let n = sock.recv(&mut buf[..]).unwrap();
    let mut resp = Cursor::new(&buf[..n]);

    if resp.get_i8() < 0 {
        return Err(());
    }

    let m = resp.get_sized_vec();

    Ok(m)
}

pub fn gen_nonce() -> Nonce {
    box_::gen_nonce()
}

