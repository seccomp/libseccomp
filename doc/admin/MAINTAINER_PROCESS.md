The libseccomp Maintainer Process
===============================================================================
https://github.com/seccomp/libseccomp

This document attempts to describe the processes that should be followed by the
various libseccomp maintainers.  It is not intended as a hard requirement, but
rather as a guiding document intended to make it easier for multiple
co-maintainers to manage the libseccomp project.

We recognize this document, like all other parts of the libseccomp project, is
not perfect.  If changes need to be made, they should be made following the
guidelines described here.

### Reviewing and Merging Patches

In a perfect world each patch would be independently reviewed and ACK'd by each
maintainer, but we recognize that is not likely to be practical for each patch.
Under normal circumstances, each patch should be ACK'd by a simple majority of
maintainers (in the case of an even number of maintainers, N/2+1) before being
merged into the repository.  Maintainers should ACK patches using a format
similar to the Linux Kernel, for example:

```
Acked-by: John Smith <john.smith@email.org>
```

The maintainer which merged the patch into the repository should add their
sign-off after ensuring that it is correct to do so (see the documentation on
submitting patches); if it is not correct for the maintainer to add their
sign-off, it is likely the patch should not be merged.  The maintainer should
add their sign-off using the standard format at the end of the patch's
metadata, for example:

```
Signed-off-by: Jane Smith <jane.smith@email.org>
```

The maintainers are encouraged to communicate with each other for many reasons,
one of which is to let the others when one is going to be unreachable for an
extended period of time.  If a patch is being held due to a lack of ACKs and
the other maintainers are not responding after a reasonable period of time (for
example, a delay of over two weeks), as long as there are no outstanding NACKs
the patch can be merged without a simple majority.

### Managing Sensitive Vulnerability Reports

The libseccomp vulnerability reporting process is documented in the SECURITY.md
document.

The maintainers should work together with the reporter to asses the validity
and seriousness of the reported vulnerability.  Whenever possible, responsible
reporting and patching practices should be followed, including notification to
the _linux-distros_ and _oss-security_ mailing lists.

* https://oss-security.openwall.org/wiki/mailing-lists/distros

### Managing the GitHub Issue Tracker

We use the GitHub issue tracker to track bugs, feature requests, and sometimes
unanswered questions.  The conventions here are intended to help distinguish
between the different uses, and prioritize within those categories.

Feature requests MUST have a "RFE:" prefix added to the issue name and use the
"enhancement" label.  Bug reports MUST a "BUG:" prefix added to the issue name
and use the "bug" label.

Issues SHOULD be prioritized using the "priority/high", "priority/medium", and
"priority/low" labels.  The meaning should hopefully be obvious.

Issues CAN be additionally labeled with the "pending/info", "pending/review",
and "pending/revision" labels to indicate that additional information is
needed, the issue/patch is pending review, and/or the patch requires changes.

### Managing the GitHub Release Milestones

There should be at least two GitHub milestones at any point in time: one for
the next major/minor release (for example, v2.5), and one for the next patch
release (for example, v2.4.2).  As issues are entered into the system, they can
be added to the milestones at the discretion of the maintainers.

### Managing the Public Mailing List

The mailing list is currently hosted on Google Groups, and while it is possible
to participate in discussions without a Google account, a Google account is
required to moderate/administer the group.  Those maintainers who do have a
Google account and wish to be added to the moderators list should be added, but
there is no requirement to do so.

Despite the term "moderator" the list is currently unmoderated and should
remain the way.

### Handling Inappropriate Community Behavior

The libseccomp project community is relatively small, and almost always
respectful and considerate.  However, there have been some limited cases of
inappropriate behavior and it is the responsibility of the maintainers to deal
with it accordingly.

As mentioned above, the maintainers are encouraged to communicate with each
other, and this communication is very important in this case.  When
inappropriate behavior is identified in the project (e.g. mailing list, GitHub,
etc.) the maintainers should talk with each other as well as the responsible
individual to try and correct the behavior.  If the individual continues to act
inappropriately the maintainers can block the individual from the project using
whatever means are available.  This should only be done as a last resort, and
with the agreement of all the maintainers.  In cases where a quick response is
necessary, a maintainer can unilaterally block an individual, but the block
should be reviewed by all the other maintainers soon afterwards.

### New Project Releases

The libseccomp release process is documented in the RELEASE_PROCESS.md
document.
