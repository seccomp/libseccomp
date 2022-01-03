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

    let mut ctx_32 = ScmpFilterContext::new(ScmpAction::KillThread)?;
    let mut ctx_64 = ScmpFilterContext::new(ScmpAction::KillThread)?;

    ctx_32.remove_arch(ScmpArch::Native)?;
    ctx_64.remove_arch(ScmpArch::Native)?;

    ctx_32.add_arch(ScmpArch::X86)?;
    ctx_64.add_arch(ScmpArch::X8664)?;

    ctx_32.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg0 == stdin().as_raw_fd() as u64)],
    )?;

    ctx_32.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg0 == stdout().as_raw_fd() as u64)],
    )?;

    ctx_32.add_rule_conditional_exact(
        ScmpAction::Allow,
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg0 == stderr().as_raw_fd() as u64)],
    )?;

    ctx_32.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("close")?)?;
    ctx_64.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("socket")?)?;
    ctx_64.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("connect")?)?;
    ctx_64.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("shutdown")?)?;

    ctx_64.merge(ctx_32)?;
    // NOTE: ctx_32 is no longer valid at this point

    util_filter_output(&opts, &ctx_64)
}
