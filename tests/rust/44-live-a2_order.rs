// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library test program
//

use anyhow::Result;
use libseccomp::*;
use std::{convert::TryInto, fs::File, io::Read, path::Path, process};
use utils::*;

const DEFAULT_ACTION_ERRNO: i32 = 100;
const DEFAULT_ACTION: ScmpAction = ScmpAction::Errno(DEFAULT_ACTION_ERRNO);

struct SizeAndRc {
    size: i32,
    expected_rc: i32,
}
impl SizeAndRc {
    pub const fn new(size: i32, expected_rc: i32) -> Self {
        Self { size, expected_rc }
    }
}

static TEST_CASE: &[SizeAndRc] = &[
    SizeAndRc::new(1, 1),
    SizeAndRc::new(10, 10),
    SizeAndRc::new(50, 50),
    SizeAndRc::new(100, -DEFAULT_ACTION_ERRNO),
    SizeAndRc::new(200, -5),
    SizeAndRc::new(256, -5),
    SizeAndRc::new(257, -6),
    SizeAndRc::new(400, -6),
    SizeAndRc::new(800, -7),
    SizeAndRc::new(1600, -8),
    SizeAndRc::new(3200, -9),
    SizeAndRc::new(4095, -9),
    SizeAndRc::new(4096, -9),
    SizeAndRc::new(4097, -10),
    SizeAndRc::new(8000, -10),
    SizeAndRc::new(8192, -10),
    SizeAndRc::new(16383, -11),
    SizeAndRc::new(16384, -11),
    SizeAndRc::new(16385, -12),
    SizeAndRc::new(35000, -12),
];

fn do_read(sz: i32, expected_rc: i32) -> Result<()> {
    let mut vec = vec![0; sz.try_into().unwrap()];
    let path = Path::new("/dev/zero");
    let mut file = File::open(path)?;

    if file.read_exact(&mut vec).is_err() && expected_rc != -util_errno() {
        process::exit(1);
    }

    Ok(())
}

fn main() -> Result<()> {
    let mut ctx = ScmpFilterContext::new(DEFAULT_ACTION)?;

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
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("close")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("rt_sigreturn")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("exit_group")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("exit")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("open")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("openat")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("stat")?)?;
    ctx.add_rule(ScmpAction::Allow, ScmpSyscall::from_name("brk")?)?;

    ctx.load()?;

    for tc in TEST_CASE {
        do_read(tc.size, tc.expected_rc)?;
    }

    process::exit(160)
}
