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
    let mut ctx = ScmpFilterContext::new(ScmpAction::KillThread)?;

    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("brk")?)?;

    // same syscall, many chains
    for iter in 0..100 {
        ctx.add_rule_conditional(
            ScmpAction::Allow,
            ScmpSyscall::from_name("chdir")?,
            &[
                scmp_cmp!($arg0 == iter),
                scmp_cmp!($arg1 != 0),
                scmp_cmp!($arg2 < libc::ssize_t::MAX as u64),
            ],
        )?;
    }

    // many syscalls, same chain
    let mut ctr = 0;
    for iter in 0..10000 {
        if ctr >= 100 {
            break;
        }

        let syscall = ScmpSyscall::from(iter);
        if syscall == ScmpSyscall::from_name("chdir")? {
            continue;
        }

        if syscall.get_name().is_ok() {
            ctx.add_rule_conditional(ScmpAction::Allow, iter, &[scmp_cmp!($arg0 != 0)])?;
            ctr += 1;
        }
    }

    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("close")?)?;

    util_filter_output(&opts, &ctx)
}
