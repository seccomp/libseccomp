/**
 * Enhanced Seccomp x86 Syscall Table
 *
 * Copyright (c) 2012 Red Hat <pmoore@redhat.com>
 * Author: Paul Moore <paul@paul-moore.com>
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
#include "arch-x86.h"

/* NOTE: based on Linux 4.15-rc7 */
const struct arch_syscall_def x86_syscall_table[] = { \
	{ "_llseek", 140 },
	{ "_newselect", 142 },
	{ "_sysctl", 149 },
	{ "accept", __PNR_accept },
	{ "accept4", 364 },
	{ "access", 33 },
	{ "acct", 51 },
	{ "add_key", 286 },
	{ "adjtimex", 124 },
	{ "afs_syscall", 137 },
	{ "alarm", 27 },
	{ "arm_fadvise64_64", __PNR_arm_fadvise64_64 },
	{ "arm_sync_file_range", __PNR_arm_sync_file_range },
	{ "arch_prctl", 384 },
	{ "bdflush", 134 },
	{ "bind", 361 },
	{ "bpf", 357 },
	{ "break", 17 },
	{ "breakpoint", __PNR_breakpoint },
	{ "brk", 45 },
	{ "cachectl", __PNR_cachectl },
	{ "cacheflush", __PNR_cacheflush },
	{ "capget", 184 },
	{ "capset", 185 },
	{ "chdir", 12 },
	{ "chmod", 15 },
	{ "chown", 182 },
	{ "chown32", 212 },
	{ "chroot", 61 },
	{ "clock_adjtime", 343 },
	{ "clock_getres", 266 },
	{ "clock_gettime", 265 },
	{ "clock_nanosleep", 267 },
	{ "clock_settime", 264 },
	{ "clone", 120 },
	{ "close", 6 },
	{ "connect", 362 },
	{ "copy_file_range", 377 },
	{ "creat", 8 },
	{ "create_module", 127 },
	{ "delete_module", 129 },
	{ "dup", 41 },
	{ "dup2", 63 },
	{ "dup3", 330 },
	{ "epoll_create", 254 },
	{ "epoll_create1", 329 },
	{ "epoll_ctl", 255 },
	{ "epoll_ctl_old", __PNR_epoll_ctl_old },
	{ "epoll_pwait", 319 },
	{ "epoll_wait", 256 },
	{ "epoll_wait_old", __PNR_epoll_wait_old },
	{ "eventfd", 323 },
	{ "eventfd2", 328 },
	{ "execve", 11 },
	{ "execveat", 358 },
	{ "exit", 1 },
	{ "exit_group", 252 },
	{ "faccessat", 307 },
	{ "fadvise64", 250 },
	{ "fadvise64_64", 272 },
	{ "fallocate", 324 },
	{ "fanotify_init", 338 },
	{ "fanotify_mark", 339 },
	{ "fchdir", 133 },
	{ "fchmod", 94 },
	{ "fchmodat", 306 },
	{ "fchown", 95 },
	{ "fchown32", 207 },
	{ "fchownat", 298 },
	{ "fcntl", 55 },
	{ "fcntl64", 221 },
	{ "fdatasync", 148 },
	{ "fgetxattr", 231 },
	{ "finit_module", 350 },
	{ "flistxattr", 234 },
	{ "flock", 143 },
	{ "fork", 2 },
	{ "fremovexattr", 237 },
	{ "fsetxattr", 228 },
	{ "fstat", 108 },
	{ "fstat64", 197 },
	{ "fstatat64", 300 },
	{ "fstatfs", 100 },
	{ "fstatfs64", 269 },
	{ "fsync", 118 },
	{ "ftime", 35 },
	{ "ftruncate", 93 },
	{ "ftruncate64", 194 },
	{ "futex", 240 },
	{ "futimesat", 299 },
	{ "get_kernel_syms", 130 },
	{ "get_mempolicy", 275 },
	{ "get_robust_list", 312 },
	{ "get_thread_area", 244 },
	{ "get_tls", __PNR_get_tls },
	{ "getcpu", 318 },
	{ "getcwd", 183 },
	{ "getdents", 141 },
	{ "getdents64", 220 },
	{ "getegid", 50 },
	{ "getegid32", 202 },
	{ "geteuid", 49 },
	{ "geteuid32", 201 },
	{ "getgid", 47 },
	{ "getgid32", 200 },
	{ "getgroups", 80 },
	{ "getgroups32", 205 },
	{ "getitimer", 105 },
	{ "getpeername", 368 },
	{ "getpgid", 132 },
	{ "getpgrp", 65 },
	{ "getpid", 20 },
	{ "getpmsg", 188 },
	{ "getppid", 64 },
	{ "getpriority", 96 },
	{ "getrandom", 355 },
	{ "getresgid", 171 },
	{ "getresgid32", 211 },
	{ "getresuid", 165 },
	{ "getresuid32", 209 },
	{ "getrlimit", 76 },
	{ "getrusage", 77 },
	{ "getsid", 147 },
	{ "getsockname", 367 },
	{ "getsockopt", 365 },
	{ "gettid", 224 },
	{ "gettimeofday", 78 },
	{ "getuid", 24 },
	{ "getuid32", 199 },
	{ "getxattr", 229 },
	{ "gtty", 32 },
	{ "idle", 112 },
	{ "init_module", 128 },
	{ "inotify_add_watch", 292 },
	{ "inotify_init", 291 },
	{ "inotify_init1", 332 },
	{ "inotify_rm_watch", 293 },
	{ "io_cancel", 249 },
	{ "io_destroy", 246 },
	{ "io_getevents", 247 },
	{ "io_setup", 245 },
	{ "io_submit", 248 },
	{ "ioctl", 54 },
	{ "ioperm", 101 },
	{ "iopl", 110 },
	{ "ioprio_get", 290 },
	{ "ioprio_set", 289 },
	{ "ipc", 117 },
	{ "kcmp", 349 },
	{ "kexec_file_load", __PNR_kexec_file_load },
	{ "kexec_load", 283 },
	{ "keyctl", 288 },
	{ "kill", 37 },
	{ "lchown", 16 },
	{ "lchown32", 198 },
	{ "lgetxattr", 230 },
	{ "link", 9 },
	{ "linkat", 303 },
	{ "listen", 363 },
	{ "listxattr", 232 },
	{ "llistxattr", 233 },
	{ "lock", 53 },
	{ "lookup_dcookie", 253 },
	{ "lremovexattr", 236 },
	{ "lseek", 19 },
	{ "lsetxattr", 227 },
	{ "lstat", 107 },
	{ "lstat64", 196 },
	{ "madvise", 219 },
	{ "mbind", 274 },
	{ "membarrier", 375 },
	{ "memfd_create", 356 },
	{ "migrate_pages", 294 },
	{ "mincore", 218 },
	{ "mkdir", 39 },
	{ "mkdirat", 296 },
	{ "mknod", 14 },
	{ "mknodat", 297 },
	{ "mlock", 150 },
	{ "mlock2", 376 },
	{ "mlockall", 152 },
	{ "mmap", 90 },
	{ "mmap2", 192 },
	{ "modify_ldt", 123 },
	{ "mount", 21 },
	{ "move_pages", 317 },
	{ "mprotect", 125 },
	{ "mpx", 56 },
	{ "mq_getsetattr", 282 },
	{ "mq_notify", 281 },
	{ "mq_open", 277 },
	{ "mq_timedreceive", 280 },
	{ "mq_timedsend", 279 },
	{ "mq_unlink", 278 },
	{ "mremap", 163 },
	{ "msgctl", __PNR_msgctl },
	{ "msgget", __PNR_msgget },
	{ "msgrcv", __PNR_msgrcv },
	{ "msgsnd", __PNR_msgsnd },
	{ "msync", 144 },
	{ "multiplexer", __PNR_multiplexer },
	{ "munlock", 151 },
	{ "munlockall", 153 },
	{ "munmap", 91 },
	{ "name_to_handle_at", 341 },
	{ "nanosleep", 162 },
	{ "newfstatat", __PNR_newfstatat },
	{ "nfsservctl", 169 },
	{ "nice", 34 },
	{ "oldfstat", 28 },
	{ "oldlstat", 84 },
	{ "oldolduname", 59 },
	{ "oldstat", 18 },
	{ "olduname", 109 },
	{ "oldwait4", __PNR_oldwait4 },
	{ "open", 5 },
	{ "open_by_handle_at", 342 },
	{ "openat", 295 },
	{ "pause", 29 },
	{ "pciconfig_iobase", __PNR_pciconfig_iobase },
	{ "pciconfig_read", __PNR_pciconfig_read },
	{ "pciconfig_write", __PNR_pciconfig_write },
	{ "perf_event_open", 336 },
	{ "personality", 136 },
	{ "pipe", 42 },
	{ "pipe2", 331 },
	{ "pivot_root", 217 },
	{ "pkey_alloc", 381 },
	{ "pkey_free", 382 },
	{ "pkey_mprotect", 380 },
	{ "poll", 168 },
	{ "ppoll", 309 },
	{ "prctl", 172 },
	{ "pread64", 180 },
	{ "preadv", 333 },
	{ "preadv2", 378 },
	{ "prlimit64", 340 },
	{ "process_vm_readv", 347 },
	{ "process_vm_writev", 348 },
	{ "prof", 44 },
	{ "profil", 98 },
	{ "pselect6", 308 },
	{ "ptrace", 26 },
	{ "putpmsg", 189 },
	{ "pwrite64", 181 },
	{ "pwritev", 334 },
	{ "pwritev2", 379 },
	{ "query_module", 167 },
	{ "quotactl", 131 },
	{ "read", 3 },
	{ "readahead", 225 },
	{ "readdir", 89 },
	{ "readlink", 85 },
	{ "readlinkat", 305 },
	{ "readv", 145 },
	{ "reboot", 88 },
	{ "recv", __PNR_recv },
	{ "recvfrom", 371 },
	{ "recvmmsg", 337 },
	{ "recvmsg", 372 },
	{ "remap_file_pages", 257 },
	{ "removexattr", 235 },
	{ "rename", 38 },
	{ "renameat", 302 },
	{ "renameat2", 353 },
	{ "request_key", 287 },
	{ "restart_syscall", 0 },
	{ "rmdir", 40 },
	{ "rt_sigaction", 174 },
	{ "rt_sigpending", 176 },
	{ "rt_sigprocmask", 175 },
	{ "rt_sigqueueinfo", 178 },
	{ "rt_sigreturn", 173 },
	{ "rt_sigsuspend", 179 },
	{ "rt_sigtimedwait", 177 },
	{ "rt_tgsigqueueinfo", 335 },
	{ "rtas", __PNR_rtas },
	{ "s390_guarded_storage", __PNR_s390_guarded_storage },
	{ "s390_pci_mmio_read", __PNR_s390_pci_mmio_read },
	{ "s390_pci_mmio_write", __PNR_s390_pci_mmio_write },
	{ "s390_runtime_instr", __PNR_s390_runtime_instr },
	{ "s390_sthyi", __PNR_s390_sthyi },
	{ "sched_get_priority_max", 159 },
	{ "sched_get_priority_min", 160 },
	{ "sched_getaffinity", 242 },
	{ "sched_getattr", 352 },
	{ "sched_getparam", 155 },
	{ "sched_getscheduler", 157 },
	{ "sched_rr_get_interval", 161 },
	{ "sched_setaffinity", 241 },
	{ "sched_setattr", 351 },
	{ "sched_setparam", 154 },
	{ "sched_setscheduler", 156 },
	{ "sched_yield", 158 },
	{ "seccomp", 354 },
	{ "security", __PNR_security },
	{ "select", 82 },
	{ "semctl", __PNR_semctl },
	{ "semget", __PNR_semget },
	{ "semop", __PNR_semop },
	{ "semtimedop", __PNR_semtimedop },
	{ "send", __PNR_send },
	{ "sendfile", 187 },
	{ "sendfile64", 239 },
	{ "sendmmsg", 345 },
	{ "sendmsg", 370 },
	{ "sendto", 369 },
	{ "set_mempolicy", 276 },
	{ "set_robust_list", 311 },
	{ "set_thread_area", 243 },
	{ "set_tid_address", 258 },
	{ "set_tls", __PNR_set_tls },
	{ "setdomainname", 121 },
	{ "setfsgid", 139 },
	{ "setfsgid32", 216 },
	{ "setfsuid", 138 },
	{ "setfsuid32", 215 },
	{ "setgid", 46 },
	{ "setgid32", 214 },
	{ "setgroups", 81 },
	{ "setgroups32", 206 },
	{ "sethostname", 74 },
	{ "setitimer", 104 },
	{ "setns", 346 },
	{ "setpgid", 57 },
	{ "setpriority", 97 },
	{ "setregid", 71 },
	{ "setregid32", 204 },
	{ "setresgid", 170 },
	{ "setresgid32", 210 },
	{ "setresuid", 164 },
	{ "setresuid32", 208 },
	{ "setreuid", 70 },
	{ "setreuid32", 203 },
	{ "setrlimit", 75 },
	{ "setsid", 66 },
	{ "setsockopt", 366 },
	{ "settimeofday", 79 },
	{ "setuid", 23 },
	{ "setuid32", 213 },
	{ "setxattr", 226 },
	{ "sgetmask", 68 },
	{ "shmat", __PNR_shmat },
	{ "shmctl", __PNR_shmctl },
	{ "shmdt", __PNR_shmdt },
	{ "shmget", __PNR_shmget },
	{ "shutdown", 373 },
	{ "sigaction", 67 },
	{ "sigaltstack", 186 },
	{ "signal", 48 },
	{ "signalfd", 321 },
	{ "signalfd4", 327 },
	{ "sigpending", 73 },
	{ "sigprocmask", 126 },
	{ "sigreturn", 119 },
	{ "sigsuspend", 72 },
	{ "socket", 359 },
	{ "socketcall", 102 },
	{ "socketpair", 360 },
	{ "splice", 313 },
	{ "spu_create", __PNR_spu_create },
	{ "spu_run", __PNR_spu_run },
	{ "ssetmask", 69 },
	{ "stat", 106 },
	{ "stat64", 195 },
	{ "statfs", 99 },
	{ "statfs64", 268 },
	{ "statx", 383 },
	{ "stime", 25 },
	{ "stty", 31 },
	{ "subpage_prot", __PNR_subpage_prot },
	{ "swapcontext", __PNR_swapcontext },
	{ "swapoff", 115 },
	{ "swapon", 87 },
	{ "switch_endian", __PNR_switch_endian },
	{ "symlink", 83 },
	{ "symlinkat", 304 },
	{ "sync", 36 },
	{ "sync_file_range", 314 },
	{ "sync_file_range2", __PNR_sync_file_range2 },
	{ "syncfs", 344 },
	{ "syscall", __PNR_syscall },
	{ "sys_debug_setcontext", __PNR_sys_debug_setcontext },
	{ "sysfs", 135 },
	{ "sysinfo", 116 },
	{ "syslog", 103 },
	{ "sysmips", __PNR_sysmips },
	{ "tee", 315 },
	{ "tgkill", 270 },
	{ "time", 13 },
	{ "timer_create", 259 },
	{ "timer_delete", 263 },
	{ "timer_getoverrun", 262 },
	{ "timer_gettime", 261 },
	{ "timer_settime", 260 },
	{ "timerfd", __PNR_timerfd },
	{ "timerfd_create", 322 },
	{ "timerfd_gettime", 326 },
	{ "timerfd_settime", 325 },
	{ "times", 43 },
	{ "tkill", 238 },
	{ "truncate", 92 },
	{ "truncate64", 193 },
	{ "tuxcall", __PNR_tuxcall },
	{ "ugetrlimit", 191 },
	{ "ulimit", 58 },
	{ "umask", 60 },
	{ "umount", 22 },
	{ "umount2", 52 },
	{ "uname", 122 },
	{ "unlink", 10 },
	{ "unlinkat", 301 },
	{ "unshare", 310 },
	{ "uselib", 86 },
	{ "userfaultfd", 374 },
	{ "usr26", __PNR_usr26 },
	{ "usr32", __PNR_usr32 },
	{ "ustat", 62 },
	{ "utime", 30 },
	{ "utimensat", 320 },
	{ "utimes", 271 },
	{ "vfork", 190 },
	{ "vhangup", 111 },
	{ "vm86", 166 },
	{ "vm86old", 113 },
	{ "vmsplice", 316 },
	{ "vserver", 273 },
	{ "wait4", 114 },
	{ "waitid", 284 },
	{ "waitpid", 7 },
	{ "write", 4 },
	{ "writev", 146 },
	{ NULL, __NR_SCMP_ERROR },
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
int x86_syscall_resolve_name(const char *name)
{
	unsigned int iter;
	const struct arch_syscall_def *table = x86_syscall_table;

	/* XXX - plenty of room for future improvement here */

	if (strcmp(name, "accept") == 0)
		return __PNR_accept;
	if (strcmp(name, "accept4") == 0)
		return __PNR_accept4;
	else if (strcmp(name, "bind") == 0)
		return __PNR_bind;
	else if (strcmp(name, "connect") == 0)
		return __PNR_connect;
	else if (strcmp(name, "getpeername") == 0)
		return __PNR_getpeername;
	else if (strcmp(name, "getsockname") == 0)
		return __PNR_getsockname;
	else if (strcmp(name, "getsockopt") == 0)
		return __PNR_getsockopt;
	else if (strcmp(name, "listen") == 0)
		return __PNR_listen;
	else if (strcmp(name, "recv") == 0)
		return __PNR_recv;
	else if (strcmp(name, "recvfrom") == 0)
		return __PNR_recvfrom;
	else if (strcmp(name, "recvmsg") == 0)
		return __PNR_recvmsg;
	else if (strcmp(name, "recvmmsg") == 0)
		return __PNR_recvmmsg;
	else if (strcmp(name, "send") == 0)
		return __PNR_send;
	else if (strcmp(name, "sendmsg") == 0)
		return __PNR_sendmsg;
	else if (strcmp(name, "sendmmsg") == 0)
		return __PNR_sendmmsg;
	else if (strcmp(name, "sendto") == 0)
		return __PNR_sendto;
	else if (strcmp(name, "setsockopt") == 0)
		return __PNR_setsockopt;
	else if (strcmp(name, "shutdown") == 0)
		return __PNR_shutdown;
	else if (strcmp(name, "socket") == 0)
		return __PNR_socket;
	else if (strcmp(name, "socketpair") == 0)
		return __PNR_socketpair;

	for (iter = 0; table[iter].name != NULL; iter++) {
		if (strcmp(name, table[iter].name) == 0)
			return table[iter].num;
	}

	return __NR_SCMP_ERROR;
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
const char *x86_syscall_resolve_num(int num)
{
	unsigned int iter;
	const struct arch_syscall_def *table = x86_syscall_table;

	/* XXX - plenty of room for future improvement here */

	if (num == __PNR_accept)
		return "accept";
	else if (num == __PNR_accept4)
		return "accept4";
	else if (num == __PNR_bind)
		return "bind";
	else if (num == __PNR_connect)
		return "connect";
	else if (num == __PNR_getpeername)
		return "getpeername";
	else if (num == __PNR_getsockname)
		return "getsockname";
	else if (num == __PNR_getsockopt)
		return "getsockopt";
	else if (num == __PNR_listen)
		return "listen";
	else if (num == __PNR_recv)
		return "recv";
	else if (num == __PNR_recvfrom)
		return "recvfrom";
	else if (num == __PNR_recvmsg)
		return "recvmsg";
	else if (num == __PNR_recvmmsg)
		return "recvmmsg";
	else if (num == __PNR_send)
		return "send";
	else if (num == __PNR_sendmsg)
		return "sendmsg";
	else if (num == __PNR_sendmmsg)
		return "sendmmsg";
	else if (num == __PNR_sendto)
		return "sendto";
	else if (num == __PNR_setsockopt)
		return "setsockopt";
	else if (num == __PNR_shutdown)
		return "shutdown";
	else if (num == __PNR_socket)
		return "socket";
	else if (num == __PNR_socketpair)
		return "socketpair";

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
const struct arch_syscall_def *x86_syscall_iterate(unsigned int spot)
{
	/* XXX - no safety checks here */
	return &x86_syscall_table[spot];
}
