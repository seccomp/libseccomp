// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;
use std::fs::File;
use std::thread::spawn;
use std::{thread, time};

// Child thread created via thread::spawn()
//
// This thread will call a disallowed syscall.  It should
// cause the entire program to die (and not just this thread.)
fn child_start() {
    // make a disallowed syscall
    let _ = File::open("/dev/null");
    // we should never get here.  seccomp should kill the entire process when open() is called.
}

fn main() -> Result<()> {
    let allowlist: [ScmpSyscall; 10] = [
        ScmpSyscall::from_name("clone")?,
        ScmpSyscall::from_name("exit")?,
        ScmpSyscall::from_name("exit_group")?,
        ScmpSyscall::from_name("futex")?,
        ScmpSyscall::from_name("madvise")?,
        ScmpSyscall::from_name("mmap")?,
        ScmpSyscall::from_name("mprotect")?,
        ScmpSyscall::from_name("munmap")?,
        ScmpSyscall::from_name("nanosleep")?,
        ScmpSyscall::from_name("set_robust_list")?,
    ];
    let mut ctx = ScmpFilterContext::new(ScmpAction::KillProcess)?;

    for syscall in allowlist {
        ctx.add_rule(ScmpAction::Allow, syscall)?;
    }

    ctx.load()?;

    spawn(child_start);
    // sleep for a bit to ensure that the child thread has time to run
    thread::sleep(time::Duration::from_secs(1));
    // we should never get here!

    Ok(())
}
