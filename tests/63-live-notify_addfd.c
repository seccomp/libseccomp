/**
 * Seccomp Library test program
 *
 * Copyright (c) 2025 Microsoft Corporation <sudpandit@microsoft.com>
 * Author: Sudipta Pandit <sudpandit@microsoft.com>
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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <seccomp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>


int send_fd(int sock, int fd)
{
	struct iovec iov = {.iov_base = "F", .iov_len = 1};
	char buffer[CMSG_SPACE(sizeof(fd))];
	memset(buffer, 0, sizeof(buffer));

	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = buffer,
		.msg_controllen = sizeof(buffer)
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fd));

	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	return sendmsg(sock, &msg, 0);
}

int recv_fd(int sock)
{
	char m_buffer[1];
	struct iovec iov = {.iov_base = m_buffer, .iov_len = 1};

	char buffer[CMSG_SPACE(sizeof(int))];
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = buffer,
		.msg_controllen = sizeof(buffer)
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	if (recvmsg(sock, &msg, 0) < 0)
		return -1;

	int fd;
	memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	return fd;
}

void child_process(scmp_filter_ctx ctx, int sock_fd)
{
	int rc;
	int ret = -1;
	int notify_fd = -1;
	char buf[128];
	ssize_t bytes_read = -1;

	rc = seccomp_load(ctx);
	if (rc < 0)
		goto out;

	rc = seccomp_notify_fd(ctx);
	if (rc < 0)
		goto out;
	notify_fd = rc;

	rc = send_fd(sock_fd, notify_fd);
	if (rc < 0) {
		rc = -errno;
		goto out;
	}

	ret = openat(AT_FDCWD, "/etc/hostname", O_RDONLY);
	if (ret < 0) {
		rc = -errno;
		goto out;
	}

	bytes_read = read(ret, buf, sizeof(buf));
	rc = bytes_read;

out:
	if (notify_fd >= 0)
		close(notify_fd);
	if (ret >= 0)
		close(ret);
	close(sock_fd);
	exit(rc);
}

int parent_process(int sock_fd)
{
	int rc;
	int notify_fd = -1;
	int new_fd = -1;
	int installed_fd = -1;
	struct seccomp_notif *req = NULL;
	struct seccomp_notif_resp *resp = NULL;
	struct seccomp_notif_addfd addfd = {0};

	rc = recv_fd(sock_fd);
	if (rc < 0) {
		rc = -errno;
		goto out;
	}
	notify_fd = rc;

	rc = seccomp_notify_alloc(&req, &resp);
	if (rc)
		goto out;

	rc = seccomp_notify_receive(notify_fd, req);
	if (rc)
		goto out;
	if (req->data.nr != __NR_openat) {
		rc = -EFAULT;
		goto out;
	}

	new_fd = openat(AT_FDCWD, "/dev/null", O_RDONLY);
	if (new_fd < 0) {
		rc = -errno;
		goto out;
	}

	memset(&addfd, 0, sizeof(addfd));
	addfd.id = req->id;
	addfd.srcfd = new_fd;
	addfd.newfd = 0;
	addfd.flags = 0;
	rc = seccomp_notify_addfd(notify_fd, &addfd);
	if (rc < 0)
		goto out;
	installed_fd = rc;

	rc = seccomp_notify_id_valid(notify_fd, req->id);
	if (rc)
		goto out;

	resp->id = req->id;
	resp->val = installed_fd;
	resp->error = 0;
	resp->flags = 0;
	rc = seccomp_notify_respond(notify_fd, resp);

out:
	if (notify_fd >= 0)
		close(notify_fd);
	if (new_fd >= 0)
		close(new_fd);
	close(sock_fd);
	seccomp_notify_free(req, resp);
	return rc;
}

int main(int argc, char *argv[])
{
	int rc, status;
	int sock_pair[2];
	scmp_filter_ctx ctx = NULL;
	pid_t pid = 0;

	ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (ctx == NULL)
		return ENOMEM;

	rc = seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, SCMP_SYS(openat), 0, NULL);
	if (rc)
		goto out;

	/* set up socket pair for sending notify_fd */
	rc = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sock_pair);
	if (rc < 0) {
		rc = -errno;
		goto out;
	}

	pid = fork();
	if (pid == 0) {
		close(sock_pair[0]); /* close the parent's end */
		child_process(ctx, sock_pair[1]);
	} else {
		close(sock_pair[1]); /* close the child's end */
		rc = parent_process(sock_pair[0]);

		if (waitpid(pid, &status, 0) != pid) {
			rc = -EFAULT;
			goto out;
		}

		if (!WIFEXITED(status)) {
			rc = -EFAULT;
			goto out;
		}
		if (WEXITSTATUS(status)) {
			rc = -EFAULT;
			goto out;
		}
	}

out:
	if (pid)
		kill(pid, SIGKILL);
	seccomp_release(ctx);

	if (rc != 0)
		return (rc < 0 ? -rc : rc);
	return 160;
}
