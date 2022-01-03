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

    ctx.remove_arch(ScmpArch::Native)?;

    ctx.add_arch(ScmpArch::X86)?;
    ctx.add_arch(ScmpArch::X8664)?;
    ctx.add_arch(ScmpArch::X32)?;
    ctx.add_arch(ScmpArch::Ppc64Le)?;
    ctx.add_arch(ScmpArch::Mipsel)?;
    ctx.add_arch(ScmpArch::Sh)?;
    ctx.add_arch(ScmpArch::Loongarch64)?;

    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("semop")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("semtimedop")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("semget")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("semctl")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("msgsnd")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("msgrcv")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("msgget")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("msgctl")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("shmat")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("shmdt")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("shmget")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("shmctl")?)?;

    util_filter_output(&opts, &ctx)
}
