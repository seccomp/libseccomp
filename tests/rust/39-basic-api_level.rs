// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::error::SeccompErrno;
use libseccomp::*;

fn main() -> Result<()> {
    let mut api: u32;
    api = get_api();
    assert!(api >= 1);

    set_api(1)?;
    api = get_api();
    assert!(api == 1);

    set_api(2)?;
    api = get_api();
    assert!(api == 2);

    set_api(3)?;
    api = get_api();
    assert!(api == 3);

    set_api(4)?;
    api = get_api();
    assert!(api == 4);

    set_api(5)?;
    api = get_api();
    assert!(api == 5);

    set_api(6)?;
    api = get_api();
    assert!(api == 6);

    set_api(7)?;
    api = get_api();
    assert!(api == 7);

    // Attempt to set a high, invalid API level
    let e = set_api(1024).unwrap_err();
    assert_eq!(e.errno().unwrap(), SeccompErrno::EINVAL);

    // Ensure that the previously set API level didn't change
    api = get_api();
    assert!(api == 7);

    Ok(())
}
