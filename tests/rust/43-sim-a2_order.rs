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

    // NOTE - a "hole" was intentionally left between 64 and 128.
    //        reads of this size should fall through to the default action -
    //        ScmpAction::KillThread in this test's case.
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg2 <= 64)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(5),
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg2 > 128)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(6),
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg2 > 256)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(7),
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg2 > 512)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(8),
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg2 > 1024)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(9),
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg2 > 2048)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(10),
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg2 > 4096)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(11),
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg2 > 8192)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(12),
        ScmpSyscall::from_name("read")?,
        &[scmp_cmp!($arg2 > 16384)],
    )?;

    // NOTE - a "hole" was intentionally left between 16384 and 32768.
    //        writes of this size should fall through to the default action -
    //        ScmpAction::KillThread in this test's case.
    ctx.add_rule_conditional(
        ScmpAction::Allow,
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg2 >= 32768)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(5),
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg2 < 128)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(6),
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg2 < 256)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(7),
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg2 < 512)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(8),
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg2 < 1024)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(9),
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg2 < 2048)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(10),
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg2 < 4096)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(11),
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg2 < 8192)],
    )?;
    ctx.add_rule_conditional(
        ScmpAction::Errno(12),
        ScmpSyscall::from_name("write")?,
        &[scmp_cmp!($arg2 < 16384)],
    )?;

    util_filter_output(&opts, &ctx)
}
