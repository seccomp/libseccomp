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

    set_api(3)?;
    let ctx = ScmpFilterContext::new(ScmpAction::Log)?;

    util_filter_output(&opts, &ctx)
}
