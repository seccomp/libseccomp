#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <seccomp.h>
#include <signal.h>
#include <syscall.h>
#include <errno.h>
#include <stdlib.h>

#include "util.h"

int main(int argc, char *argv[])
{
	int rc, fd = -1, status;
	struct seccomp_notif *req = NULL;
	struct seccomp_notif_resp *resp = NULL;
	scmp_filter_ctx ctx = NULL;
	pid_t pid = 0;
	struct util_options opts;

	rc = util_getopt(argc, argv, &opts);
	if (rc < 0)
		goto out;

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL)
		return ENOMEM;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

	rc = seccomp_attr_set(ctx, SCMP_FLTATR_NEW_LISTENER, 1);
	if (rc)
		goto out;

	rc = seccomp_rule_add_exact(ctx, SCMP_ACT_USER_NOTIF, SCMP_SYS(getpid), 0, NULL);
	if (rc)
		goto out;

	rc  = seccomp_load(ctx);
	if (rc < 0)
		goto out;

	rc = fd = seccomp_notif_fd(ctx);
	if (fd < 0)
		goto out;

#define MAGIC 0x1122334455667788UL
	pid = fork();
	if (pid == 0)
		exit(syscall(SCMP_SYS(getpid)) != MAGIC);

	rc = seccomp_notif_alloc(&req, &resp);
	if (rc)
		goto out;

	rc = seccomp_notif_receive(fd, req);
	if (rc)
		goto out;

	if (req->data.nr != SCMP_SYS(getpid)) {
		rc = -EINVAL;
		goto out;
	}

	resp->id = req->id;
	resp->val = MAGIC;
	resp->error = 0;

	rc = seccomp_notif_send_resp(fd, resp);
	if (rc)
		goto out;

	rc = -EINVAL;
	if (waitpid(pid, &status, 0) != pid)
		goto out;

	if (!WIFEXITED(status))
		goto out;

	if (WEXITSTATUS(status))
		goto out;

	rc = 0;
out:
	if (req)
		seccomp_notif_free(req, resp);
	if (pid)
		kill(pid, SIGKILL);
	seccomp_release(ctx);
	if (fd >= 0)
		close(fd);
	return (rc < 0 ? -rc : rc);
}
