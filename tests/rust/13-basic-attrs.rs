// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::error::SeccompErrno;
use libseccomp::*;
use utils::*;

fn main() -> Result<()> {
    let opts = util_getopt();
    let val = u32::MAX;

    set_api(5)?;
    let mut ctx = ScmpFilterContext::new(ScmpAction::Allow)?;

    // for ActDefault
    assert_eq!(ctx.get_act_default()?, ScmpAction::Allow);
    let e = ctx
        .set_filter_attr(ScmpFilterAttr::ActDefault, val)
        .unwrap_err();
    assert_eq!(e.errno().unwrap(), SeccompErrno::EACCES);

    // for ActBadArch
    ctx.set_act_badarch(ScmpAction::Allow)?;
    assert_eq!(ctx.get_act_badarch()?, ScmpAction::Allow);

    // for CtlNnp
    ctx.set_ctl_nnp(false)?;
    ctx.get_ctl_nnp()?;

    // for CtlTsync
    if let Err(e) = ctx.set_ctl_tsync(true) {
        assert_eq!(e.errno().unwrap(), SeccompErrno::EOPNOTSUPP);
    }
    assert!(ctx.get_ctl_tsync()?);

    // for ApiTskip
    ctx.set_filter_attr(ScmpFilterAttr::ApiTskip, val)?;
    ctx.get_filter_attr(ScmpFilterAttr::ApiTskip)?;

    // for CtlLog
    ctx.set_ctl_log(true)?;
    assert!(ctx.get_ctl_log()?);

    // for CtlSsb
    ctx.set_ctl_ssb(true)?;
    assert!(ctx.get_ctl_ssb()?);

    // for CtlOptimize
    ctx.set_ctl_optimize(2)?;
    assert_eq!(ctx.get_ctl_optimize()?, 2);

    // for ApiSysRawRc
    ctx.set_api_sysrawrc(true)?;
    assert!(ctx.get_api_sysrawrc()?);

    // for CtlWaitKill
    // SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV has been available since Linux 5.19.
    if check_api(7, ScmpVersion::from((2, 6, 0))).unwrap() {
        ctx.set_ctl_waitkill(true)?;
        assert!(ctx.get_ctl_waitkill()?);
    }

    util_filter_output(&opts, &ctx)
}
