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

    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("socket")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("bind")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("connect")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("listen")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("accept")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("getsockname")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("getpeername")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("socketpair")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("send")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("recv")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("sendto")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("recvfrom")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("shutdown")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("setsockopt")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("getsockopt")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("sendmsg")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("recvmsg")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("accept4")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("sendmmsg")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("recvmmsg")?)?;

    util_filter_output(&opts, &ctx)
}
