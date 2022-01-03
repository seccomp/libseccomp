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
    set_api(1)?;
    let mut ctx = ScmpFilterContext::new(ScmpAction::Errno(100))?;

    ctx.remove_arch(ScmpArch::Native)?;
    ctx.add_arch(ScmpArch::X8664)?;

    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from(1001),
        &[
            scmp_cmp!($arg0 == 1),
            scmp_cmp!($arg1 & 0xf == 2),
            scmp_cmp!($arg2 == 3),
        ],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from(1001),
        &[scmp_cmp!($arg0 == 1), scmp_cmp!($arg1 & 0xf == 1)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 2)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from(1000),
        &[scmp_cmp!($arg0 == 1)],
    )?;

    util_filter_output(&opts, &ctx)
}
