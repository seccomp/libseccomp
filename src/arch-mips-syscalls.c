/**
 * Enhanced Seccomp MIPS Specific Code
 *
 * Copyright (c) 2014 Imagination Technologies Ltd.
 * Author: Markos Chandras <markos.chandras@imgtec.com>
 *
 */

/*
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License as
 * published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses>.
 */

#include <string.h>

#include <seccomp.h>

#include "arch.h"
#include "arch-mips.h"
#include "syscall-hashmap.h"

/* O32 ABI */
#define __SCMP_NR_BASE		4000

/* NOTE: based on Linux 4.15-rc7 */
const struct arch_syscall_def mips_syscall_table[] = { \
	{ "_llseek", (__SCMP_NR_BASE + 140) },
	{ "_newselect", (__SCMP_NR_BASE + 142) },
	{ "_sysctl", (__SCMP_NR_BASE + 153) },
	{ "accept", (__SCMP_NR_BASE + 168) },
	{ "accept4", (__SCMP_NR_BASE + 334) },
	{ "access", (__SCMP_NR_BASE + 33) },
	{ "acct", (__SCMP_NR_BASE + 51) },
	{ "add_key", (__SCMP_NR_BASE + 280) },
	{ "adjtimex", (__SCMP_NR_BASE + 124) },
	{ "afs_syscall", __SCMP_NR_BASE + 137 },
	{ "alarm", (__SCMP_NR_BASE + 27) },
	{ "arm_fadvise64_64", __PNR_arm_fadvise64_64 },
	{ "arm_sync_file_range", __PNR_arm_sync_file_range },
	{ "arch_prctl", __PNR_arch_prctl },
	{ "bdflush", (__SCMP_NR_BASE + 134) },
	{ "bind", (__SCMP_NR_BASE + 169) },
	{ "bpf", (__SCMP_NR_BASE + 355) },
	{ "break", __SCMP_NR_BASE + 17 },
	{ "breakpoint", __PNR_breakpoint },
	{ "brk", (__SCMP_NR_BASE + 45) },
	{ "cachectl", (__SCMP_NR_BASE + 148) },
	{ "cacheflush", (__SCMP_NR_BASE + 147) },
	{ "capget", (__SCMP_NR_BASE + 204) },
	{ "capset", (__SCMP_NR_BASE + 205) },
	{ "chdir", (__SCMP_NR_BASE + 12) },
	{ "chmod", (__SCMP_NR_BASE + 15) },
	{ "chown", (__SCMP_NR_BASE + 202) },
	{ "chown32", (__PNR_chown32) },
	{ "chroot", (__SCMP_NR_BASE + 61) },
	{ "clock_adjtime", (__SCMP_NR_BASE + 341) },
	{ "clock_getres", (__SCMP_NR_BASE + 264) },
	{ "clock_gettime", (__SCMP_NR_BASE + 263) },
	{ "clock_nanosleep", (__SCMP_NR_BASE + 265) },
	{ "clock_settime", (__SCMP_NR_BASE + 262) },
	{ "clone", (__SCMP_NR_BASE + 120) },
	{ "close", (__SCMP_NR_BASE + 6) },
	{ "connect", (__SCMP_NR_BASE + 170) },
	{ "copy_file_range", (__SCMP_NR_BASE + 360) },
	{ "creat", (__SCMP_NR_BASE + 8) },
	{ "create_module", __SCMP_NR_BASE + 127 },
	{ "delete_module", (__SCMP_NR_BASE + 129) },
	{ "dup", (__SCMP_NR_BASE + 41) },
	{ "dup2", (__SCMP_NR_BASE + 63) },
	{ "dup3", (__SCMP_NR_BASE + 327) },
	{ "epoll_create", (__SCMP_NR_BASE + 248) },
	{ "epoll_create1", (__SCMP_NR_BASE + 326) },
	{ "epoll_ctl", (__SCMP_NR_BASE + 249) },
	{ "epoll_ctl_old", __PNR_epoll_ctl_old },
	{ "epoll_pwait", (__SCMP_NR_BASE + 313) },
	{ "epoll_wait", (__SCMP_NR_BASE + 250) },
	{ "epoll_wait_old", __PNR_epoll_wait_old },
	{ "eventfd", (__SCMP_NR_BASE + 319) },
	{ "eventfd2", (__SCMP_NR_BASE + 325) },
	{ "execve", (__SCMP_NR_BASE + 11) },
	{ "execveat", (__SCMP_NR_BASE + 356) },
	{ "exit", (__SCMP_NR_BASE + 1) },
	{ "exit_group", (__SCMP_NR_BASE + 246) },
	{ "faccessat", (__SCMP_NR_BASE + 300) },
	{ "fadvise64", __SCMP_NR_BASE + 254 },
	{ "fadvise64_64", __PNR_fadvise64_64 },
	{ "fallocate", (__SCMP_NR_BASE + 320) },
	{ "fanotify_init", (__SCMP_NR_BASE + 336) },
	{ "fanotify_mark", (__SCMP_NR_BASE + 337) },
	{ "fchdir", (__SCMP_NR_BASE + 133) },
	{ "fchmod", (__SCMP_NR_BASE + 94) },
	{ "fchmodat", (__SCMP_NR_BASE + 299) },
	{ "fchown", (__SCMP_NR_BASE + 95) },
	{ "fchown32", (__PNR_fchown32) },
	{ "fchownat", (__SCMP_NR_BASE + 291) },
	{ "fcntl", (__SCMP_NR_BASE + 55) },
	{ "fcntl64", (__SCMP_NR_BASE + 220) },
	{ "fdatasync", (__SCMP_NR_BASE + 152) },
	{ "fgetxattr", (__SCMP_NR_BASE + 229) },
	{ "finit_module", (__SCMP_NR_BASE + 348) },
	{ "flistxattr", (__SCMP_NR_BASE + 232) },
	{ "flock", (__SCMP_NR_BASE + 143) },
	{ "fork", (__SCMP_NR_BASE + 2) },
	{ "fremovexattr", (__SCMP_NR_BASE + 235) },
	{ "fsetxattr", (__SCMP_NR_BASE + 226) },
	{ "fstat", (__SCMP_NR_BASE + 108) },
	{ "fstat64", (__SCMP_NR_BASE + 215) },
	{ "fstatat64", (__SCMP_NR_BASE + 293) },
	{ "fstatfs", (__SCMP_NR_BASE + 100) },
	{ "fstatfs64", (__SCMP_NR_BASE + 256) },
	{ "fsync", (__SCMP_NR_BASE + 118) },
	{ "ftime", (__SCMP_NR_BASE + 35) },
	{ "ftruncate", (__SCMP_NR_BASE + 93) },
	{ "ftruncate64", (__SCMP_NR_BASE + 212) },
	{ "futex", (__SCMP_NR_BASE + 238) },
	{ "futimesat", (__SCMP_NR_BASE + 292) },
	{ "get_kernel_syms", (__SCMP_NR_BASE + 130) },
	{ "get_mempolicy", (__SCMP_NR_BASE + 269) },
	{ "get_robust_list", (__SCMP_NR_BASE + 310) },
	{ "get_thread_area", __PNR_get_thread_area },
	{ "get_tls", __PNR_get_tls },
	{ "getcpu", (__SCMP_NR_BASE + 312) },
	{ "getcwd", (__SCMP_NR_BASE + 203) },
	{ "getdents", (__SCMP_NR_BASE + 141) },
	{ "getdents64", (__SCMP_NR_BASE + 219) },
	{ "getegid", (__SCMP_NR_BASE + 50) },
	{ "getegid32", __PNR_getegid32 },
	{ "geteuid", (__SCMP_NR_BASE + 49) },
	{ "geteuid32", __PNR_geteuid32 },
	{ "getgid", (__SCMP_NR_BASE + 47) },
	{ "getgid32", __PNR_getgid32 },
	{ "getgroups", (__SCMP_NR_BASE + 80) },
	{ "getgroups32", __PNR_getgroups32 },
	{ "getitimer", (__SCMP_NR_BASE + 105) },
	{ "getpeername", (__SCMP_NR_BASE + 171) },
	{ "getpgid", (__SCMP_NR_BASE + 132) },
	{ "getpgrp", (__SCMP_NR_BASE + 65) },
	{ "getpid", (__SCMP_NR_BASE + 20) },
	{ "getpmsg", (__SCMP_NR_BASE + 208) },
	{ "getppid", (__SCMP_NR_BASE + 64) },
	{ "getpriority", (__SCMP_NR_BASE + 96) },
	{ "getrandom", (__SCMP_NR_BASE + 353) },
	{ "getresgid", (__SCMP_NR_BASE + 191) },
	{ "getresgid32", __PNR_getresgid32 },
	{ "getresuid", (__SCMP_NR_BASE + 186) },
	{ "getresuid32", __PNR_getresuid32 },
	{ "getrlimit", (__SCMP_NR_BASE + 76) },
	{ "getrusage", (__SCMP_NR_BASE + 77) },
	{ "getsid", (__SCMP_NR_BASE + 151) },
	{ "getsockname", (__SCMP_NR_BASE + 172) },
	{ "getsockopt", (__SCMP_NR_BASE + 173) },
	{ "gettid", (__SCMP_NR_BASE + 222) },
	{ "gettimeofday", (__SCMP_NR_BASE + 78) },
	{ "getuid", (__SCMP_NR_BASE + 24) },
	{ "getuid32", __PNR_getuid32 },
	{ "getxattr", (__SCMP_NR_BASE + 227) },
	{ "gtty", (__SCMP_NR_BASE + 32) },
	{ "idle", (__SCMP_NR_BASE + 112) },
	{ "init_module", (__SCMP_NR_BASE + 128) },
	{ "inotify_add_watch", (__SCMP_NR_BASE + 285) },
	{ "inotify_init", (__SCMP_NR_BASE + 284) },
	{ "inotify_init1", (__SCMP_NR_BASE + 329) },
	{ "inotify_rm_watch", (__SCMP_NR_BASE + 286) },
	{ "io_cancel", (__SCMP_NR_BASE + 245) },
	{ "io_destroy", (__SCMP_NR_BASE + 242) },
	{ "io_getevents", (__SCMP_NR_BASE + 243) },
	{ "io_pgetevents", (__SCMP_NR_BASE + 368) },
	{ "io_setup", (__SCMP_NR_BASE + 241) },
	{ "io_submit", (__SCMP_NR_BASE + 244) },
	{ "ioctl", (__SCMP_NR_BASE + 54) },
	{ "ioperm", (__SCMP_NR_BASE + 101) },
	{ "iopl", (__SCMP_NR_BASE + 110) },
	{ "ioprio_get", (__SCMP_NR_BASE + 315) },
	{ "ioprio_set", (__SCMP_NR_BASE + 314) },
	{ "ipc", (__SCMP_NR_BASE + 117) },
	{ "kcmp", (__SCMP_NR_BASE + 347)  },
	{ "kexec_file_load", __PNR_kexec_file_load },
	{ "kexec_load", (__SCMP_NR_BASE + 311) },
	{ "keyctl", (__SCMP_NR_BASE + 282) },
	{ "kill", (__SCMP_NR_BASE + 37) },
	{ "lchown", (__SCMP_NR_BASE + 16) },
	{ "lchown32", __PNR_lchown32 },
	{ "lgetxattr", (__SCMP_NR_BASE + 228) },
	{ "link", (__SCMP_NR_BASE + 9) },
	{ "linkat", (__SCMP_NR_BASE + 296) },
	{ "listen", (__SCMP_NR_BASE + 174) },
	{ "listxattr", (__SCMP_NR_BASE + 230) },
	{ "llistxattr", (__SCMP_NR_BASE + 231) },
	{ "lock", (__SCMP_NR_BASE + 53) },
	{ "lookup_dcookie", (__SCMP_NR_BASE + 247) },
	{ "lremovexattr", (__SCMP_NR_BASE + 234) },
	{ "lseek", (__SCMP_NR_BASE + 19) },
	{ "lsetxattr", (__SCMP_NR_BASE + 225) },
	{ "lstat", (__SCMP_NR_BASE + 107) },
	{ "lstat64", (__SCMP_NR_BASE + 214) },
	{ "madvise", (__SCMP_NR_BASE + 218) },
	{ "mbind", (__SCMP_NR_BASE + 268) },
	{ "membarrier", (__SCMP_NR_BASE + 358) },
	{ "memfd_create", (__SCMP_NR_BASE + 354) },
	{ "migrate_pages", (__SCMP_NR_BASE + 287) },
	{ "mincore", (__SCMP_NR_BASE + 217) },
	{ "mkdir", (__SCMP_NR_BASE + 39) },
	{ "mkdirat", (__SCMP_NR_BASE + 289) },
	{ "mknod", (__SCMP_NR_BASE + 14) },
	{ "mknodat", (__SCMP_NR_BASE + 290) },
	{ "mlock", (__SCMP_NR_BASE + 154) },
	{ "mlock2", (__SCMP_NR_BASE + 359) },
	{ "mlockall", (__SCMP_NR_BASE + 156) },
	{ "mmap", (__SCMP_NR_BASE + 90) },
	{ "mmap2", (__SCMP_NR_BASE + 210) },
	{ "modify_ldt", (__SCMP_NR_BASE + 123) },
	{ "mount", (__SCMP_NR_BASE + 21) },
	{ "move_pages", (__SCMP_NR_BASE + 308) },
	{ "mprotect", (__SCMP_NR_BASE + 125) },
	{ "mpx", (__SCMP_NR_BASE + 56) },
	{ "mq_getsetattr", (__SCMP_NR_BASE + 276) },
	{ "mq_notify", (__SCMP_NR_BASE + 275) },
	{ "mq_open", (__SCMP_NR_BASE + 271) },
	{ "mq_timedreceive", (__SCMP_NR_BASE + 274) },
	{ "mq_timedsend", (__SCMP_NR_BASE + 273) },
	{ "mq_unlink", (__SCMP_NR_BASE + 272) },
	{ "mremap", (__SCMP_NR_BASE + 167) },
	{ "msgctl", __PNR_msgctl },
	{ "msgget", __PNR_msgget },
	{ "msgrcv", __PNR_msgrcv },
	{ "msgsnd", __PNR_msgsnd },
	{ "msync", (__SCMP_NR_BASE + 144) },
	{ "multiplexer", __PNR_multiplexer },
	{ "munlock", (__SCMP_NR_BASE + 155) },
	{ "munlockall", (__SCMP_NR_BASE + 157) },
	{ "munmap", (__SCMP_NR_BASE + 91) },
	{ "name_to_handle_at", (__SCMP_NR_BASE + 339) },
	{ "nanosleep", (__SCMP_NR_BASE + 166) },
	{ "newfstatat", __PNR_newfstatat },
	{ "nfsservctl", (__SCMP_NR_BASE + 189) },
	{ "nice", (__SCMP_NR_BASE + 34) },
	{ "oldfstat", __PNR_oldfstat },
	{ "oldlstat", __PNR_oldlstat },
	{ "oldolduname", __PNR_oldolduname },
	{ "oldstat", __PNR_oldstat },
	{ "olduname", __PNR_olduname },
	{ "oldwait4", __PNR_oldwait4 },
	{ "open", (__SCMP_NR_BASE + 5) },
	{ "open_by_handle_at", (__SCMP_NR_BASE + 340) },
	{ "openat", (__SCMP_NR_BASE + 288) },
	{ "pause", (__SCMP_NR_BASE + 29) },
	{ "pciconfig_iobase", __PNR_pciconfig_iobase },
	{ "pciconfig_read", __PNR_pciconfig_read },
	{ "pciconfig_write", __PNR_pciconfig_write },
	{ "perf_event_open", (__SCMP_NR_BASE + 333) },
	{ "personality", (__SCMP_NR_BASE + 136) },
	{ "pipe", (__SCMP_NR_BASE + 42) },
	{ "pipe2", (__SCMP_NR_BASE + 328) },
	{ "pivot_root", (__SCMP_NR_BASE + 216) },
	{ "pkey_alloc", (__SCMP_NR_BASE + 364) },
	{ "pkey_free", (__SCMP_NR_BASE + 365) },
	{ "pkey_mprotect", (__SCMP_NR_BASE + 363) },
	{ "poll", (__SCMP_NR_BASE + 188) },
	{ "ppoll", (__SCMP_NR_BASE + 302) },
	{ "prctl", (__SCMP_NR_BASE + 192) },
	{ "pread64", (__SCMP_NR_BASE + 200) },
	{ "preadv", (__SCMP_NR_BASE + 330) },
	{ "preadv2", (__SCMP_NR_BASE + 361) },
	{ "prlimit64", (__SCMP_NR_BASE + 338) },
	{ "process_vm_readv", (__SCMP_NR_BASE + 345) },
	{ "process_vm_writev", (__SCMP_NR_BASE + 346) },
	{ "prof", (__SCMP_NR_BASE + 44) },
	{ "profil", (__SCMP_NR_BASE + 98) },
	{ "pselect6", (__SCMP_NR_BASE + 301) },
	{ "ptrace", (__SCMP_NR_BASE + 26) },
	{ "putpmsg", (__SCMP_NR_BASE + 209) },
	{ "pwrite64", (__SCMP_NR_BASE + 201) },
	{ "pwritev", (__SCMP_NR_BASE + 331) },
	{ "pwritev2", (__SCMP_NR_BASE + 362) },
	{ "query_module", (__SCMP_NR_BASE + 187) },
	{ "quotactl", (__SCMP_NR_BASE + 131) },
	{ "read", (__SCMP_NR_BASE + 3) },
	{ "readahead", (__SCMP_NR_BASE + 223) },
	{ "readdir", (__SCMP_NR_BASE + 89) },
	{ "readlink", (__SCMP_NR_BASE + 85) },
	{ "readlinkat", (__SCMP_NR_BASE + 298) },
	{ "readv", (__SCMP_NR_BASE + 145) },
	{ "reboot", (__SCMP_NR_BASE + 88) },
	{ "recv", (__SCMP_NR_BASE + 175) },
	{ "recvfrom", (__SCMP_NR_BASE + 176) },
	{ "recvmmsg", (__SCMP_NR_BASE + 335) },
	{ "recvmsg", (__SCMP_NR_BASE + 177) },
	{ "remap_file_pages", (__SCMP_NR_BASE + 251) },
	{ "removexattr", (__SCMP_NR_BASE + 233) },
	{ "rename", (__SCMP_NR_BASE + 38) },
	{ "renameat", (__SCMP_NR_BASE + 295) },
	{ "renameat2", (__SCMP_NR_BASE + 351) },
	{ "request_key", (__SCMP_NR_BASE + 281) },
	{ "restart_syscall", (__SCMP_NR_BASE + 253) },
	{ "rmdir", (__SCMP_NR_BASE + 40) },
	{ "rseq", (__SCMP_NR_BASE + 367) },
	{ "rt_sigaction", (__SCMP_NR_BASE + 194) },
	{ "rt_sigpending", (__SCMP_NR_BASE + 196) },
	{ "rt_sigprocmask", (__SCMP_NR_BASE + 195) },
	{ "rt_sigqueueinfo", (__SCMP_NR_BASE + 198) },
	{ "rt_sigreturn", (__SCMP_NR_BASE + 193) },
	{ "rt_sigsuspend", (__SCMP_NR_BASE + 199) },
	{ "rt_sigtimedwait", (__SCMP_NR_BASE + 197) },
	{ "rt_tgsigqueueinfo", (__SCMP_NR_BASE + 332) },
	{ "rtas", __PNR_rtas },
	{ "s390_guarded_storage", __PNR_s390_guarded_storage },
	{ "s390_pci_mmio_read", __PNR_s390_pci_mmio_read },
	{ "s390_pci_mmio_write", __PNR_s390_pci_mmio_write },
	{ "s390_runtime_instr", __PNR_s390_runtime_instr },
	{ "s390_sthyi", __PNR_s390_sthyi },
	{ "sched_get_priority_max", (__SCMP_NR_BASE + 163) },
	{ "sched_get_priority_min", (__SCMP_NR_BASE + 164) },
	{ "sched_getaffinity", (__SCMP_NR_BASE + 240) },
	{ "sched_getattr", (__SCMP_NR_BASE + 350) },
	{ "sched_getparam", (__SCMP_NR_BASE + 159) },
	{ "sched_getscheduler", (__SCMP_NR_BASE + 161) },
	{ "sched_rr_get_interval", (__SCMP_NR_BASE + 165) },
	{ "sched_setaffinity", (__SCMP_NR_BASE + 239) },
	{ "sched_setattr", (__SCMP_NR_BASE + 349) },
	{ "sched_setparam", (__SCMP_NR_BASE + 158) },
	{ "sched_setscheduler", (__SCMP_NR_BASE + 160) },
	{ "sched_yield", (__SCMP_NR_BASE + 162) },
	{ "seccomp", (__SCMP_NR_BASE + 352) },
	{ "security", __PNR_security },
	{ "select", __PNR_select },
	{ "semctl", __PNR_semctl },
	{ "semget", __PNR_semget },
	{ "semop", __PNR_semop },
	{ "semtimedop", __PNR_semtimedop },
	{ "send", (__SCMP_NR_BASE + 178) },
	{ "sendfile", (__SCMP_NR_BASE + 207) },
	{ "sendfile64", (__SCMP_NR_BASE + 237) },
	{ "sendmmsg", (__SCMP_NR_BASE + 343) },
	{ "sendmsg", (__SCMP_NR_BASE + 179) },
	{ "sendto", (__SCMP_NR_BASE + 180) },
	{ "set_mempolicy", (__SCMP_NR_BASE + 270) },
	{ "set_robust_list", (__SCMP_NR_BASE + 309) },
	{ "set_thread_area", (__SCMP_NR_BASE + 283) },
	{ "set_tid_address", (__SCMP_NR_BASE + 252) },
	{ "set_tls", __PNR_set_tls },
	{ "setdomainname", (__SCMP_NR_BASE + 121) },
	{ "setfsgid", (__SCMP_NR_BASE + 139) },
	{ "setfsgid32", __PNR_setfsgid32 },
	{ "setfsuid", (__SCMP_NR_BASE + 138) },
	{ "setfsuid32", __PNR_setfsuid32 },
	{ "setgid", (__SCMP_NR_BASE + 46) },
	{ "setgid32", __PNR_setgid32 },
	{ "setgroups", (__SCMP_NR_BASE + 81) },
	{ "setgroups32", __PNR_setgroups32 },
	{ "sethostname", (__SCMP_NR_BASE + 74) },
	{ "setitimer", (__SCMP_NR_BASE + 104) },
	{ "setns", (__SCMP_NR_BASE + 344) },
	{ "setpgid", (__SCMP_NR_BASE + 57) },
	{ "setpriority", (__SCMP_NR_BASE + 97) },
	{ "setregid", (__SCMP_NR_BASE + 71) },
	{ "setregid32", __PNR_setregid32 },
	{ "setresgid", (__SCMP_NR_BASE + 190) },
	{ "setresgid32", __PNR_setresgid32 },
	{ "setresuid", (__SCMP_NR_BASE + 185) },
	{ "setresuid32", __PNR_setresuid32 },
	{ "setreuid", (__SCMP_NR_BASE + 70) },
	{ "setreuid32", __PNR_setreuid32 },
	{ "setrlimit", (__SCMP_NR_BASE + 75) },
	{ "setsid", (__SCMP_NR_BASE + 66) },
	{ "setsockopt", (__SCMP_NR_BASE + 181) },
	{ "settimeofday", (__SCMP_NR_BASE + 79) },
	{ "setuid", (__SCMP_NR_BASE + 23) },
	{ "setuid32", __PNR_setuid32 },
	{ "setxattr", (__SCMP_NR_BASE + 224) },
	{ "sgetmask", (__SCMP_NR_BASE + 68) },
	{ "shmat", __PNR_shmat },
	{ "shmctl", __PNR_shmctl },
	{ "shmdt", __PNR_shmdt },
	{ "shmget", __PNR_shmget },
	{ "shutdown", (__SCMP_NR_BASE + 182) },
	{ "sigaction", (__SCMP_NR_BASE + 67) },
	{ "sigaltstack", (__SCMP_NR_BASE + 206) },
	{ "signal", (__SCMP_NR_BASE + 48) },
	{ "signalfd", (__SCMP_NR_BASE + 317) },
	{ "signalfd4", (__SCMP_NR_BASE + 324) },
	{ "sigpending", (__SCMP_NR_BASE + 73) },
	{ "sigprocmask", (__SCMP_NR_BASE + 126) },
	{ "sigreturn", (__SCMP_NR_BASE + 119) },
	{ "sigsuspend", (__SCMP_NR_BASE + 72) },
	{ "socket", (__SCMP_NR_BASE + 183) },
	{ "socketcall", (__SCMP_NR_BASE + 102) },
	{ "socketpair", (__SCMP_NR_BASE + 184) },
	{ "splice", (__SCMP_NR_BASE + 304) },
	{ "spu_create", __PNR_spu_create },
	{ "spu_run", __PNR_spu_run },
	{ "ssetmask", (__SCMP_NR_BASE + 69) },
	{ "stat", (__SCMP_NR_BASE + 106) },
	{ "stat64", (__SCMP_NR_BASE + 213) },
	{ "statfs", (__SCMP_NR_BASE + 99) },
	{ "statfs64", (__SCMP_NR_BASE + 255) },
	{ "statx", (__SCMP_NR_BASE + 366) },
	{ "stime", (__SCMP_NR_BASE + 25) },
	{ "stty", (__SCMP_NR_BASE + 31) },
	{ "subpage_prot", __PNR_subpage_prot },
	{ "swapcontext", __PNR_swapcontext },
	{ "swapoff", (__SCMP_NR_BASE + 115) },
	{ "swapon", (__SCMP_NR_BASE + 87) },
	{ "switch_endian", __PNR_switch_endian },
	{ "symlink", (__SCMP_NR_BASE + 83) },
	{ "symlinkat", (__SCMP_NR_BASE + 297) },
	{ "sync", (__SCMP_NR_BASE + 36) },
	{ "sync_file_range", (__SCMP_NR_BASE + 305) },
	{ "sync_file_range2", __PNR_sync_file_range2 },
	{ "syncfs", (__SCMP_NR_BASE + 342) },
	{ "syscall", (__SCMP_NR_BASE + 0) },
	{ "sys_debug_setcontext", __PNR_sys_debug_setcontext },
	{ "sysfs", (__SCMP_NR_BASE + 135) },
	{ "sysinfo", (__SCMP_NR_BASE + 116) },
	{ "syslog", (__SCMP_NR_BASE + 103) },
	{ "sysmips", (__SCMP_NR_BASE + 149) },
	{ "tee", (__SCMP_NR_BASE + 306) },
	{ "tgkill", (__SCMP_NR_BASE + 266) },
	{ "time", (__SCMP_NR_BASE + 13) },
	{ "timer_create", (__SCMP_NR_BASE + 257) },
	{ "timer_delete", (__SCMP_NR_BASE + 261) },
	{ "timer_getoverrun", (__SCMP_NR_BASE + 260) },
	{ "timer_gettime", (__SCMP_NR_BASE + 259) },
	{ "timer_settime", (__SCMP_NR_BASE + 258) },
	{ "timerfd", (__SCMP_NR_BASE + 318) },
	{ "timerfd_create", (__SCMP_NR_BASE + 321) },
	{ "timerfd_gettime", (__SCMP_NR_BASE + 322) },
	{ "timerfd_settime", (__SCMP_NR_BASE + 323) },
	{ "times", (__SCMP_NR_BASE + 43) },
	{ "tkill", (__SCMP_NR_BASE + 236) },
	{ "truncate", (__SCMP_NR_BASE + 92) },
	{ "truncate64", (__SCMP_NR_BASE + 211) },
	{ "tuxcall", __PNR_tuxcall },
	{ "ugetrlimit", __PNR_ugetrlimit },
	{ "ulimit", (__SCMP_NR_BASE + 58) },
	{ "umask", (__SCMP_NR_BASE + 60) },
	{ "umount", (__SCMP_NR_BASE + 22) },
	{ "umount2", (__SCMP_NR_BASE + 52) },
	{ "uname", (__SCMP_NR_BASE + 122) },
	{ "unlink", (__SCMP_NR_BASE + 10) },
	{ "unlinkat", (__SCMP_NR_BASE + 294) },
	{ "unshare", (__SCMP_NR_BASE + 303) },
	{ "uselib", (__SCMP_NR_BASE + 86) },
	{ "userfaultfd",  (__SCMP_NR_BASE + 357) },
	{ "usr26", __PNR_usr26 },
	{ "usr32", __PNR_usr32 },
	{ "ustat", (__SCMP_NR_BASE + 62) },
	{ "utime", (__SCMP_NR_BASE + 30) },
	{ "utimensat", (__SCMP_NR_BASE + 316) },
	{ "utimes", (__SCMP_NR_BASE + 267) },
	{ "vfork", __PNR_vfork },
	{ "vhangup", (__SCMP_NR_BASE + 111) },
	{ "vm86", (__SCMP_NR_BASE + 113) },
	{ "vm86old", __PNR_vm86old },
	{ "vmsplice", (__SCMP_NR_BASE + 307) },
	{ "vserver", (__SCMP_NR_BASE + 277) },
	{ "wait4", (__SCMP_NR_BASE + 114) },
	{ "waitid", (__SCMP_NR_BASE + 278) },
	{ "waitpid", (__SCMP_NR_BASE + 7) },
	{ "write", (__SCMP_NR_BASE +  4) },
	{ "writev", (__SCMP_NR_BASE + 146) },
	{ NULL, __NR_SCMP_ERROR },
};

const struct syscall_hashmap_entry mips_syscall_hashmap[] = {
#ifndef GENERATING_HASHMAP
#include "arch-mips-syscall-hashmap.c"
#endif
};

/**
 * Resolve a syscall name to a number
 * @param name the syscall name
 *
 * Resolve the given syscall name to the syscall number using the syscall table.
 * Returns the syscall number on success, including negative pseudo syscall
 * numbers; returns __NR_SCMP_ERROR on failure.
 *
 */
int mips_syscall_resolve_name(const char *name)
{
	return syscall_hashmap_resolve(mips_syscall_hashmap,
		sizeof(mips_syscall_hashmap) / sizeof(*mips_syscall_hashmap), name);
}

/**
 * Resolve a syscall number to a name
 * @param num the syscall number
 *
 * Resolve the given syscall number to the syscall name using the syscall table.
 * Returns a pointer to the syscall name string on success, including pseudo
 * syscall names; returns NULL on failure.
 *
 */
const char *mips_syscall_resolve_num(int num)
{
	unsigned int iter;
	const struct arch_syscall_def *table = mips_syscall_table;

	/* XXX - plenty of room for future improvement here */
	for (iter = 0; table[iter].num != __NR_SCMP_ERROR; iter++) {
		if (num == table[iter].num)
			return table[iter].name;
	}

	return NULL;
}

/**
 * Iterate through the syscall table and return the syscall mapping
 * @param spot the offset into the syscall table
 *
 * Return the syscall mapping at position @spot or NULL on failure.  This
 * function should only ever be used internally by libseccomp.
 *
 */
const struct arch_syscall_def *mips_syscall_iterate(unsigned int spot)
{
	/* XXX - no safety checks here */
	return &mips_syscall_table[spot];
}
