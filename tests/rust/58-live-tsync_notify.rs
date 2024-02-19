// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libc::{fork, getpid, syscall, waitpid, SYS_getpid, WEXITSTATUS, WIFEXITED};
use libseccomp::*;
use std::process::exit;

fn main() -> Result<()> {
    let mut status: i32 = 0;
    let magic = unsafe { getpid() };
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    ctx.set_ctl_tsync(true)?;
    ctx.add_rule(ScmpAction::Notify, ScmpSyscall::from_name("getpid")?)?;
    ctx.load()?;

    let fd = ctx.get_notify_fd()?;
    let pid = unsafe { fork() };
    if pid == 0 {
        exit((unsafe { syscall(SYS_getpid) } != magic as i64) as i32);
    }

    let req = ScmpNotifReq::receive(fd)?;
    assert!(req.data.syscall == ScmpSyscall::from(SYS_getpid as i32));
    notify_id_valid(fd, req.id)?;

    let resp = ScmpNotifResp::new(req.id, magic as i64, 0, 0);
    resp.respond(fd)?;

    assert!(unsafe { waitpid(pid, &mut status, 0) } == pid);
    assert!(WIFEXITED(status));
    assert!(WEXITSTATUS(status) == 0);

    exit(160);
}
