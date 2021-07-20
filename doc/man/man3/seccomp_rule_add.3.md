NAME
====

seccomp_rule_add, seccomp_rule_add_exact - Add a seccomp filter
rule

SYNOPSIS
========

    #include <seccomp.h>

    typedef void * scmp_filter_ctx;

    int SCMP_SYS(syscall_name);

    struct scmp_arg_cmp SCMP_CMP(unsigned int arg,
     enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A0(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A1(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A2(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A3(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A4(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A5(enum scmp_compare op, ...);

    struct scmp_arg_cmp SCMP_CMP64(unsigned int arg,
     enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A0_64(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A1_64(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A2_64(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A3_64(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A4_64(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A5_64(enum scmp_compare op, ...);

    struct scmp_arg_cmp SCMP_CMP32(unsigned int arg,
     enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A0_32(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A1_32(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A2_32(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A3_32(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A4_32(enum scmp_compare op, ...);
    struct scmp_arg_cmp SCMP_A5_32(enum scmp_compare op, ...);

    int seccomp_rule_add(scmp_filter_ctx ctx, uint32_t action,
     int syscall, unsigned int arg_cnt, ...);
    int seccomp_rule_add_exact(scmp_filter_ctx ctx, uint32_t action,
     int syscall, unsigned int arg_cnt, ...);

    int seccomp_rule_add_array(scmp_filter_ctx ctx,
     uint32_t action, int syscall,
     unsigned int arg_cnt,
     const struct scmp_arg_cmp *arg_array);
    int seccomp_rule_add_exact_array(scmp_filter_ctx ctx,
     uint32_t action, int syscall,
     unsigned int arg_cnt,
     const struct scmp_arg_cmp *arg_array);

    Link with -lseccomp.

DESCRIPTION
===========

The **seccomp_rule_add**(), **seccomp_rule_add_array**(),
**seccomp_rule_add_exact**(), and
**seccomp_rule_add_exact_array**() functions all add a new filter
rule to the current seccomp filter. The **seccomp_rule_add**() and
**seccomp_rule_add_array**() functions will make a "best effort" to
add the rule as specified, but may alter the rule slightly due to
architecture specifics (e.g. internal rewriting of multiplexed syscalls,
like socket and ipc functions on x86). The
**seccomp_rule_add_exact**() and
**seccomp_rule_add_exact_array**() functions will attempt to add the
rule exactly as specified so it may behave differently on different
architectures. While it does not guarantee a exact filter ruleset,
**seccomp_rule_add**() and **seccomp_rule_add_array**() do
guarantee the same behavior regardless of the architecture.

The newly added filter rule does not take effect until the entire filter
is loaded into the kernel using **seccomp_load**(3). When adding rules
to a filter, it is important to consider the impact of previously loaded
filters; see the **seccomp_load**(3) documentation for more
information.

All of the filter rules supplied by the calling application are combined
into a union, with additional logic to eliminate redundant syscall
filters. For example, if a rule is added which allows a given syscall
with a specific set of argument values and later a rule is added which
allows the same syscall regardless the argument values then the first,
more specific rule, is effectively dropped from the filter by the second
more generic rule.

The **SCMP_CMP**(), **SCMP_CMP64**(), **SCMP_A{0-5}**(), and
**SCMP_A{0-5}_64**() macros generate a scmp_arg_cmp structure for
use with the above functions. The **SCMP_CMP**() and **SCMP_CMP64**()
macros allows the caller to specify an arbitrary argument along with the
comparison operator, 64-bit mask, and 64-bit datum values where the
**SCMP_A{0-5}**() and **SCMP_A{0-5}_64**() macros are specific to a
certain argument.

The **SCMP_CMP32**() and **SCMP_A{0-5}_32**() macros are similar to
the variants above, but they take 32-bit mask and 32-bit datum values.

It is recommended that whenever possible developers avoid using the
**SCMP_CMP**() and **SCMP_A{0-5}**() macros and use the variants which
are explicitly 32 or 64-bit. This should help eliminate problems caused
by an unwanted sign extension of negative datum values.

If syscall argument comparisons are included in the filter rule, all of
the comparisons must be true for the rule to match.

When adding syscall argument comparisons to the filter it is important
to remember that while it is possible to have multiple comparisons in a
single rule, you can only compare each argument once in a single rule.
In other words, you can not have multiple comparisons of the 3rd syscall
argument in a single rule.

In a filter containing multiple architectures, it is an error to add a
filter rule for a syscall that does not exist in all of the filter's
architectures.

While it is possible to specify the *syscall* value directly using the
standard **__NR_syscall** values, in order to ensure proper operation
across multiple architectures it is highly recommended to use the
**SCMP_SYS**() macro instead. See the EXAMPLES section below. It is
also important to remember that regardless of the architectures present
in the filter, the syscall numbers used in filter rules are interpreted
in the context of the native architecture.

Starting with Linux v4.8, there may be a need to create a rule with a
syscall value of -1 to allow tracing programs to skip a syscall
invocation; in order to create a rule with a -1 syscall value it is
necessary to first set the **SCMP_FLTATR_API_TSKIP** attribute. See
**seccomp_attr_set**(3) for more information.

The filter context *ctx* is the value returned by the call to
**seccomp_init**(3).

Valid *action* values are as follows:

**SCMP_ACT_KILL**

:   The thread will be killed by the kernel when it calls a syscall that
    matches the filter rule.

**SCMP_ACT_KILL_PROCESS**

:   The process will be killed by the kernel when it calls a syscall
    that matches the filter rule.

**SCMP_ACT_TRAP**

:   The thread will throw a SIGSYS signal when it calls a syscall that
    matches the filter rule.

**SCMP_ACT_ERRNO(uint16_t errno)**

:   The thread will receive a return value of *errno* when it calls a
    syscall that matches the filter rule.

**SCMP_ACT_TRACE(uint16_t msg_num)**

:   If the thread is being traced and the tracing process specified the
    **PTRACE_O_TRACESECCOMP** option in the call to **ptrace**(2), the
    tracing process will be notified, via **PTRACE_EVENT_SECCOMP** ,
    and the value provided in *msg_num* can be retrieved using the
    **PTRACE_GETEVENTMSG** option.

**SCMP_ACT_LOG**

:   The seccomp filter will have no effect on the thread calling the
    syscall if it matches the filter rule but the syscall will be
    logged.

**SCMP_ACT_ALLOW**

:   The seccomp filter will have no effect on the thread calling the
    syscall if it matches the filter rule.

**SCMP_ACT_NOTIFY**

:   A monitoring process will be notified when a process running the
    seccomp filter calls a syscall that matches the filter rule. The
    process that invokes the syscall waits in the kernel until the
    monitoring process has responded via **seccomp_notify_respond(3)**
    .

When a filter utilizing **SCMP_ACT_NOTIFY** is loaded into the kernel,
the kernel generates a notification fd that must be used to communicate
between the monitoring process and the process(es) being filtered. See
**seccomp_notif_fd(3)** for more information.

Valid comparison *op* values are as follows:

**SCMP_CMP_NE**

:   Matches when the argument value is not equal to the datum value,
    example:

SCMP_CMP( *arg* , SCMP_CMP_NE , *datum* )

**SCMP_CMP_LT**

:   Matches when the argument value is less than the datum value,
    example:

SCMP_CMP( *arg* , SCMP_CMP_LT , *datum* )

**SCMP_CMP_LE**

:   Matches when the argument value is less than or equal to the datum
    value, example:

SCMP_CMP( *arg* , SCMP_CMP_LE , *datum* )

**SCMP_CMP_EQ**

:   Matches when the argument value is equal to the datum value,
    example:

SCMP_CMP( *arg* , SCMP_CMP_EQ , *datum* )

**SCMP_CMP_GE**

:   Matches when the argument value is greater than or equal to the
    datum value, example:

SCMP_CMP( *arg* , SCMP_CMP_GE , *datum* )

**SCMP_CMP_GT**

:   Matches when the argument value is greater than the datum value,
    example:

SCMP_CMP( *arg* , SCMP_CMP_GT , *datum* )

**SCMP_CMP_MASKED_EQ**

:   Matches when the masked argument value is equal to the masked datum
    value, example:

SCMP_CMP( *arg* , SCMP_CMP_MASKED_EQ , *mask* , *datum* )

RETURN VALUE
============

The **SCMP_SYS**() macro returns a value suitable for use as the
*syscall* value in the **seccomp_rule_add***() functions. In a
similar manner, the **SCMP_CMP**() and **SCMP_A***() macros return
values suitable for use as argument comparisons in the
**seccomp_rule_add**() and **seccomp_rule_add_exact**() functions.

The **seccomp_rule_add**(), **seccomp_rule_add_array**(),
**seccomp_rule_add_exact**(), and
**seccomp_rule_add_exact_array**() functions return zero on success
or one of the following error codes on failure:

**-EDOM**

:   Architecture specific failure.

**-EEXIST**

:   The rule already exists.

**-EFAULT**

:   Internal libseccomp failure.

**-EINVAL**

:   Invalid input, either the context or architecture token is invalid.

**-ENOMEM**

:   The library was unable to allocate enough memory.

**-EOPNOTSUPP**

:   The library doesn't support the particular operation.

EXAMPLES
========

    #include <fcntl.h>
    #include <seccomp.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <stddef.h>

    #define BUF_SIZE	256

    int main(int argc, char *argv[])
    {
    	int rc = -1;
    	scmp_filter_ctx ctx;
    	struct scmp_arg_cmp arg_cmp[] = { SCMP_A0(SCMP_CMP_EQ, 2) };
    	int fd;
    	unsigned char buf[BUF_SIZE];

    	ctx = seccomp_init(SCMP_ACT_KILL);
    	if (ctx == NULL)
    		goto out;

    	/* ... */

    	fd = open("file.txt", 0);

    	/* ... */

    	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    	if (rc < 0)
    		goto out;

    	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    	if (rc < 0)
    		goto out;

    	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    	if (rc < 0)
    		goto out;

    	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 3,
    			      SCMP_A0(SCMP_CMP_EQ, fd),
    			      SCMP_A1(SCMP_CMP_EQ, (scmp_datum_t)buf),
    			      SCMP_A2(SCMP_CMP_LE, BUF_SIZE));
    	if (rc < 0)
    		goto out;

    	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
    			      SCMP_CMP(0, SCMP_CMP_EQ, fd));
    	if (rc < 0)
    		goto out;

    	rc = seccomp_rule_add_array(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,
    			            arg_cmp);
    	if (rc < 0)
    		goto out;

    	rc = seccomp_load(ctx);
    	if (rc < 0)
    		goto out;

    	/* ... */

    out:
    	seccomp_release(ctx);
    	return -rc;
    }

NOTES
=====

While the seccomp filter can be generated independent of the kernel,
kernel support is required to load and enforce the seccomp filter
generated by libseccomp.

The libseccomp project site, with more information and the source code
repository, can be found at https://github.com/seccomp/libseccomp. This
tool, as well as the libseccomp library, is currently under development,
please report any bugs at the project site or directly to the author.

AUTHOR
======

Paul Moore <paul@paul-moore.com>

SEE ALSO
========

**seccomp_syscall_resolve_name_rewrite**(3),
**seccomp_syscall_priority**(3), **seccomp_load**(3),
**seccomp_attr_set**(3)
