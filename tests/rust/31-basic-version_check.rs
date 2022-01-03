// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;

fn main() -> Result<()> {
    assert!(ScmpVersion::current().is_ok());

    Ok(())
}
