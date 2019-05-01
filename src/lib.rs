mod box_;
mod server;
mod seccomp;
mod ipc;

#[cfg(test)]
mod tests {
    use super::box_;

    #[test]
    fn it_works() {
        box_::init().unwrap();

        let (ourpk, oursk) = box_::gen_keypair();
        // normally theirpk is sent by the other party
        let (theirpk, theirsk) = box_::gen_keypair();

        let nonce = box_::gen_nonce();
        let plaintext = b"some data";

        let ciphertext = box_::seal(plaintext, &nonce, &theirpk, &oursk);

        let their_plaintext = box_::open(&ciphertext, &nonce, &ourpk, &theirsk).unwrap();
        assert_eq!(plaintext, &their_plaintext[..]);
    }
}

