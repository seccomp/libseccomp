// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::error::SeccompErrno;
use libseccomp::*;
use nix::unistd::{sysconf, SysconfVar};
use std::os::unix::io::FromRawFd;
use std::os::unix::prelude::OwnedFd;
use utils::*;

fn main() -> Result<()> {
    let opts = util_getopt();

    // set_syscall_priority error
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
    let mut e = ctx.set_syscall_priority(-10, 1).unwrap_err();
    assert_eq!(e.errno().unwrap(), SeccompErrno::EINVAL);

    // add_rule errors
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
    e = ctx
        .add_rule(ScmpAction::Allow, ScmpSyscall::from_name("read")?)
        .unwrap_err();
    assert_eq!(e.errno().unwrap(), SeccompErrno::EACCES);
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
    e = ctx
        .add_rule_exact(ScmpAction::KillThread, ScmpSyscall::from(-10001))
        .unwrap_err();
    assert_eq!(e.errno().unwrap(), SeccompErrno::EDOM);

    // add_rule_exact error
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
    ctx.remove_arch(ScmpArch::Native)?;
    ctx.add_arch(ScmpArch::X86)?;
    e = ctx
        .add_rule_conditional_exact(
            ScmpAction::KillThread,
            ScmpSyscall::from_name("socket")?,
            &[scmp_cmp!($arg0 == 2)],
        )
        .unwrap_err();
    assert_eq!(e.errno().unwrap(), SeccompErrno::EINVAL);

    // Errno values beyond MAX_ERRNO
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
    e = ctx
        .add_rule(ScmpAction::Errno(0xffff), ScmpSyscall::from(0))
        .unwrap_err();
    assert_eq!(e.errno().unwrap(), SeccompErrno::EINVAL);

    // export_pfc error
    let ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
    e = ctx
        .export_pfc(unsafe {
            OwnedFd::from_raw_fd((sysconf(SysconfVar::OPEN_MAX)?.unwrap() - 1) as i32)
        })
        .unwrap_err();
    assert_eq!(e.errno().unwrap(), SeccompErrno::ECANCELED);

    // export_bpf error
    let ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
    e = ctx
        .export_bpf(unsafe {
            OwnedFd::from_raw_fd((sysconf(SysconfVar::OPEN_MAX)?.unwrap() - 1) as i32)
        })
        .unwrap_err();
    assert_eq!(e.errno().unwrap(), SeccompErrno::ECANCELED);

    // seccomp notify errors
    let api = get_api();
    if api >= 5 {
        let ctx = ScmpFilterContext::new(ScmpAction::Allow)?;
        assert!(notify_id_valid(-1, 0).is_err());
        assert!(ctx.get_notify_fd().is_err());
    }

    util_filter_output(&opts, &ctx)
}
