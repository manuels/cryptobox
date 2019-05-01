use std::os::unix::io::RawFd;

use seccomp;

fn allow_read_fd(fd: RawFd) -> seccomp::Rule {
    seccomp::Rule::new(0 /* read on x86_64 */,
            seccomp::Compare::arg(0)
                .with(fd as _)
                .using(seccomp::Op::Eq)
                .build().unwrap(),
            seccomp::Action::Allow
        )
}

fn allow_write_fd(fd: RawFd) -> seccomp::Rule {
    seccomp::Rule::new(1 /* write on x86_64 */,
            seccomp::Compare::arg(0)
                .with(fd as _)
                .using(seccomp::Op::Eq)
                .build().unwrap(),
            seccomp::Action::Allow
        )
}

fn allow_recv_from_fd(fd: RawFd) -> seccomp::Rule {
    seccomp::Rule::new(45 /* recv_from on x86_64 */,
            seccomp::Compare::arg(0)
                .with(fd as _)
                .using(seccomp::Op::Eq)
                .build().unwrap(),
            seccomp::Action::Allow
        )
}

fn allow_send_to_fd(fd: RawFd) -> seccomp::Rule {
    seccomp::Rule::new(44 /* send_to on x86_64 */,
            seccomp::Compare::arg(0)
                .with(fd as _)
                .using(seccomp::Op::Eq)
                .build().unwrap(),
            seccomp::Action::Allow
        )
}

fn allow_getrandom() -> seccomp::Rule {
    seccomp::Rule::new(318 /* getrandom on x86_64 */,
            seccomp::Compare::arg(0)
                .with(0)
                .using(seccomp::Op::Ne)
                .build().unwrap(),
            seccomp::Action::Allow
        )
}

pub fn run_seccomp(ipc_fd: RawFd) {
    let errno = seccomp::Action::Errno(nix::errno::Errno::EPERM as _);

    let mut ctx = seccomp::Context::default(errno).unwrap();

    ctx.add_rule(allow_read_fd(0)).unwrap();
    ctx.add_rule(allow_write_fd(1)).unwrap();
    ctx.add_rule(allow_write_fd(2)).unwrap();

    ctx.add_rule(allow_recv_from_fd(ipc_fd)).unwrap();
    ctx.add_rule(allow_send_to_fd(ipc_fd)).unwrap();
    ctx.add_rule(allow_write_fd(ipc_fd)).unwrap(); // sneaky GNU libc maps sendto() to write()

    ctx.add_rule(allow_getrandom()).unwrap();

    ctx.load().unwrap();
}


