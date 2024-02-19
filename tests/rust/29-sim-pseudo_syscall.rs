// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;
use utils::*;

fn main() -> Result<()> {
    let opts = util_getopt();
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    // NOTE: we have to be careful here because some ABIs use syscall
    //       offsets which could interfere with our test, x86 is safe
    ctx.remove_arch(ScmpArch::Native)?;
    ctx.add_arch(ScmpArch::X86)?;

    // ScmpSyscall::from_name(sysmips) == 4294957190 (unsigned)
    ctx.add_rule(ScmpAction::KillThread, ScmpSyscall::from_name("sysmips")?)?;
    assert!(ctx
        .add_rule_exact(ScmpAction::KillThread, ScmpSyscall::from_name("sysmips")?)
        .is_err());
    // -10001 == 4294957295 (unsigned)
    assert!(ctx
        .add_rule_exact(ScmpAction::KillThread, ScmpSyscall::from(-10001))
        .is_err());

    util_filter_output(&opts, &ctx)
}
