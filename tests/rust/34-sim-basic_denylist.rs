// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;
use std::io::{stderr, stdin, stdout};
use std::os::unix::io::AsRawFd;
use utils::*;

fn main() -> Result<()> {
    let opts = util_getopt();
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg0 == stdin().as_raw_fd() as u64)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg0 == stdout().as_raw_fd() as u64)],
    )?;
    ctx.add_rule_conditional_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg0 == stderr().as_raw_fd() as u64)],
    )?;
    ctx.add_rule_exact(ScmpAction::KillThread, ScmpSyscall::from_name("close")?)?;
    ctx.add_rule_exact(
        ScmpAction::KillThread,
        ScmpSyscall::from_name("rt_sigreturn")?,
    )?;

    util_filter_output(&opts, &ctx)
}
