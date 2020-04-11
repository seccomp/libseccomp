NAME
====

seccomp\_notify\_alloc, seccomp\_notify\_free, seccomp\_notify\_receive,
seccomp\_notify\_respond, seccomp\_notify\_id\_valid,
seccomp\_notify\_fd - Manage seccomp notifications

SYNOPSIS
========

    #include <seccomp.h>

    int seccomp_notify_alloc(struct seccomp_notif **req, struct seccomp_notif_resp **resp)
    void seccomp_notify_free(struct seccomp_notif *req, struct seccomp_notif_resp *resp)
    int seccomp_notify_receive(int fd, struct seccomp_notif *req)
    int seccomp_notify_respond(int fd, struct seccomp_notif_resp *resp)
    int seccomp_notify_id_valid(int fd, uint64_t id)
    int seccomp_notify_fd(const scmp_filter_ctx ctx)

    Link with -lseccomp.

DESCRIPTION
===========

The **seccomp\_notify\_alloc**() function dynamically allocates enough
memory for a seccomp notification and response. Note that one should
always use these functions and not depend on the structure sizes in
headers, since the size can vary depending on the kernel version. This
function takes care to ask the kernel how big each structure should be,
and allocates the right amount of memory. The
**seccomp\_notify\_free**() function frees memory allocated by
**seccomp\_notify\_alloc**().

The **seccomp\_notify\_receive**() function receives a notification from
a seccomp notify fd (obtained from **seccomp\_notify\_fd**()).

The **seccomp\_notify\_respond**() function sends a response to a
particular notification. The id field should be the same as the id from
the request, so that the kernel knows which request this response
corresponds to.

The **seccomp\_notify\_id\_valid**() function checks to see if the
syscall from a particualr notification request is still valid, i.e. if
the task is still alive. See NOTES below for details on race conditions.

The **seccomp\_notify\_fd**() returns the notification fd of a filter
after it has been loaded.

RETURN VALUE
============

The **seccomp\_notify\_alloc**(), **seccomp\_notify\_receive**(), and
**seccomp\_notify\_respond**() functions all return 0 on success, -1 on
failure.

The **seccomp\_notify\_id\_valid**() returns 0 if the id is valid, and
-ENOENT if it is not.

The **seccomp\_notify\_fd**() returns the notification fd of the loaded
filter.

NOTES
=====

Care should be taken to avoid two different time of check/time of use
errors. First, after opening any resources relevant to the pid for a
notification (e.g. /proc/pid/mem for reading tracee memory to make
policy decisions), applications should call
**seccomp\_notify\_id\_valid**() to make sure that the resources the
application has opened correspond to the right pid, i.e. that the pid
didn\'t die and a different task take its place.

Second, the classic time of check/time of use issue with seccomp memory
should also be avoided: applications should copy any memory they wish to
use to make decisions from the tracee into its own address space before
applying any policy decisions, since a multi-threaded tracee may edit
the memory at any time, including after it\'s used to make a policy
decision.

A complete example of how to avoid these two races is available in the
Linux Kernel source tree at **/samples/seccomp/user-trap.c.**

AUTHOR
======

Tycho Andersen \<tycho\@tycho.ws\>
