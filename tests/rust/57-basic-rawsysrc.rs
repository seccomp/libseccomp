// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libc::EBADF;
use libseccomp::*;
use nix::unistd::{close, dup};
use std::os::unix::io::FromRawFd;
use std::os::unix::prelude::OwnedFd;
use utils::*;

fn main() -> Result<()> {
    set_api(3)?;
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    ctx.set_api_sysrawrc(true)?;

    //  we must use a closed/invalid fd for this to work
    let fd = dup(2)?;
    close(fd)?;
    assert!(ctx.export_pfc(unsafe { OwnedFd::from_raw_fd(fd) }).is_err());
    assert!(util_errno() == EBADF);

    Ok(())
}
