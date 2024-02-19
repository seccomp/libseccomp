// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;
use std::env;
use std::process;
use utils::*;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        process::exit(1);
    }

    let action = util_action_parse(&args[1])?;
    if action == ScmpAction::Trap {
        util_trap_install()?;
    }

    let mut ctx = ScmpFilterContext::new(action)?;

    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("rt_sigreturn")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("exit_group")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("sigaltstack")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("munmap")?)?;

    ctx.load()?;

    let mut ret: i32 = util_file_write("/dev/null");
    if ret == 0 {
        ret = 160;
    }

    process::exit(ret);
}
