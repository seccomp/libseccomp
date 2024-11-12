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
    let api = get_api();
    assert_ne!(api, 0);

    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    if api >= 2 {
        ctx.set_ctl_tsync(true)?;
    }
    if api >= 3 {
        ctx.set_ctl_log(true)?;
    }
    if api >= 4 {
        ctx.set_ctl_ssb(true)?;
    }

    ctx.load()?;

    util_filter_output(&opts, &ctx)
}
