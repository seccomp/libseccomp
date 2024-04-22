// SPDX-License-Identifier: LGPL-2.1-only
//
// Copyright 2024 Sony Group Corporation
//
// Seccomp Library utility code for tests
//

use anyhow::{anyhow, Result};
use clap::Parser;
use libseccomp::*;
use nix::sys::signal::SigmaskHow::SIG_UNBLOCK;
use nix::sys::signal::{sigaction, sigprocmask, SaFlags, SigAction, SigHandler, SigSet, SIGSYS};
use std::fs::OpenOptions;
use std::io::Write;

#[derive(Parser)]
#[clap(version, author)]
pub struct Opts {
    /// Generate BPF output
    #[clap(short, long)]
    pub bpf: bool,
    /// Generate PFC output [default]
    #[clap(short, long)]
    pub pfc: bool,
}

// This function parses the arguments passed to the test from the command line.
// Returns the Opts on success.
pub fn util_getopt() -> Opts {
    let mut opts = Opts::parse();
    if !opts.bpf && !opts.pfc {
        opts.pfc = true;
    }

    opts
}

// This function outputs the seccomp filter to stdout in either BPF or PFC
// format depending on the test paramaeters supplied by Opts.
pub fn util_filter_output(opts: &Opts, ctx: &ScmpFilterContext) -> Result<()> {
    if opts.bpf {
        ctx.export_bpf(std::io::stdout())?;
    } else {
        ctx.export_pfc(std::io::stdout())?;
    }

    Ok(())
}

// This function outputs the seccomp action corresponding
// to the action name received as parameter
pub fn util_action_parse(action: &str) -> Result<ScmpAction> {
    match action.to_lowercase().as_str() {
        "kill" => Ok(ScmpAction::KillThread),
        "kill_process" => Ok(ScmpAction::KillProcess),
        "trap" => Ok(ScmpAction::Trap),
        "errno" => Ok(ScmpAction::Errno(163)),
        "trace" => Err(anyhow!("trace is not yet supported")),
        "allow" => Ok(ScmpAction::Allow),
        "log" => Ok(ScmpAction::Log),
        _ => Err(anyhow!("{} is an invalid action", action)),
    }
}

// This function outputs an error representing the last OS error which occurred.
pub fn util_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

// This function writes a string to a file that is present at the
// path provided as the parameter
pub fn util_file_write(path: &str) -> i32 {
    let buff: &str = "testing";

    let file = OpenOptions::new().write(true).create(true).open(path);
    if file.is_err() {
        return util_errno();
    }

    if file.unwrap().write_all(buff.as_bytes()).is_err() {
        return util_errno();
    }

    0
}

// This function install a TRAP action signal handler
extern "C" fn trap_handler(_: i32, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
    unsafe { libc::_exit(161) };
}

// Install a TRAP action signal handler
//
// This function installs the TRAP action signal handler and is based on
// examples from Will Drewry and Kees Cook.  Returns zero on success, negative
// values on failure.
pub fn util_trap_install() -> Result<(), nix::Error> {
    let sig_action = SigAction::new(
        SigHandler::SigAction(trap_handler),
        SaFlags::SA_SIGINFO,
        SigSet::empty(),
    );

    let mut sig_mask = SigSet::empty();
    sig_mask.add(SIGSYS);

    unsafe {
        sigaction(SIGSYS, &sig_action)?;
    }
    sigprocmask(SIG_UNBLOCK, Some(&sig_mask), Some(&mut SigSet::empty()))?;

    Ok(())
}
