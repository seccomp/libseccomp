// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;
use nix::fcntl::{open, OFlag};
use nix::sys::stat::Mode;
use nix::unistd::write;
use std::env;
use std::process;
use utils::*;

const DENYLIST: [ScmpSyscall; 24] = [
    ScmpSyscall::new("times"),
    ScmpSyscall::new("ptrace"),
    ScmpSyscall::new("getuid"),
    ScmpSyscall::new("syslog"),
    ScmpSyscall::new("getgid"),
    ScmpSyscall::new("setuid"),
    ScmpSyscall::new("setgid"),
    ScmpSyscall::new("geteuid"),
    ScmpSyscall::new("getegid"),
    ScmpSyscall::new("setpgid"),
    ScmpSyscall::new("getppid"),
    ScmpSyscall::new("getpgrp"),
    ScmpSyscall::new("setsid"),
    ScmpSyscall::new("setreuid"),
    ScmpSyscall::new("setregid"),
    ScmpSyscall::new("getgroups"),
    ScmpSyscall::new("setgroups"),
    ScmpSyscall::new("setresuid"),
    ScmpSyscall::new("getresuid"),
    ScmpSyscall::new("setresgid"),
    ScmpSyscall::new("getresgid"),
    ScmpSyscall::new("getpgid"),
    ScmpSyscall::new("setfsuid"),
    ScmpSyscall::new("setfsgid"),
];

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        process::exit(1);
    }

    let action = util_action_parse(&args[1])?;
    assert_eq!(action, ScmpAction::Allow);
    util_trap_install()?;

    let fd = open(
        "/dev/null",
        OFlag::O_WRONLY | OFlag::O_CREAT,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )?;
    let buf = "testing";
    let buf_len = buf.len();
    let mut ctx = ScmpFilterContext::new(ScmpAction::Trap)?;

    ctx.set_ctl_optimize(2)?;

    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg0 == fd as u64)],
    )?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("close")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("rt_sigreturn")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("exit_group")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("sigaltstack")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("munmap")?)?;

    for deny in DENYLIST {
        ctx.add_rule(ScmpAction::KillThread, deny)?;
    }

    ctx.load()?;

    if write(fd, buf.as_bytes()) == Ok(buf_len) {
        process::exit(160);
    } else {
        process::exit(util_errno())
    }
}
