/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <errno.h>
#include <fcntl.h>

#include "aul_api.h"
#include "aul_sock.h"
#include "aul_util.h"

#define MAX_NR_OF_DESCRIPTORS 2

static int __connect_client_sock(int sockfd, const struct sockaddr *saptr, socklen_t salen,
		   int nsec);

static inline void __set_sock_option(int fd, int cli)
{
	int size;
	struct timeval tv = { 5, 200 * 1000 };	/* 5.2 sec */

	size = AUL_SOCK_MAXBUFF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (cli)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

API int aul_sock_create_server(int pid, uid_t uid)
{
	struct sockaddr_un saddr;
	struct sockaddr_un p_saddr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	/*  support above version 2.6.27*/
	if (fd < 0) {
		if (errno == EINVAL) {
			fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0) {
				_E("second chance - socket create error");
				return -1;
			}
		} else {
			_E("socket error");
			return -1;
		}
	}

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, sizeof(saddr.sun_path), "/run/user/%d/%d", uid, pid);
	unlink(saddr.sun_path);

	/* labeling to socket for SMACK */
	if (getuid() == 0) {	/* this is meaningful iff current user is ROOT */
		if (fsetxattr(fd, "security.SMACK64IPOUT", "@", 1, 0) < 0) {
			/* in case of unsupported filesystem on 'socket' */
			/* or permission error by using 'emulator', bypass*/
			if ((errno != EOPNOTSUPP) && (errno != EPERM)) {
				_E("labeling to socket(IPOUT) error");
				close(fd);
				return -1;
			}
		}
		if (fsetxattr(fd, "security.SMACK64IPIN", "*", 1, 0) < 0) {
			/* in case of unsupported filesystem on 'socket' */
			/* or permission error by using 'emulator', bypass*/
			if ((errno != EOPNOTSUPP) && (errno != EPERM)) {
				_E("labeling to socket(IPIN) error");
				close(fd);
				return -1;
			}
		}
	}

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		_E("bind error");
		close(fd);
		return -1;
	}

	if (chmod(saddr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
		/* Flawfinder: ignore*/
		_E("failed to change the socket permission");
		close(fd);
		return -1;
	}

	__set_sock_option(fd, 0);

	if (listen(fd, 128) == -1) {
		_E("listen error");
		close(fd);
		return -1;
	}

	/* support app launched by shell script */
	if (pid > 0) {
		int pgid;
		pgid = getpgid(pid);
		if (pgid > 1) {
			snprintf(p_saddr.sun_path, sizeof(p_saddr.sun_path),
					"/run/user/%d/%d", uid, pgid);
			if (link(saddr.sun_path, p_saddr.sun_path) < 0) {
				if (errno == EEXIST)
					_D("pg path - already exists");
				else
					_E("pg path - unknown create error");
			}
		}
	}

	return fd;
}

static int __create_client_sock(int pid, uid_t uid)
{
	int fd = -1;
	struct sockaddr_un saddr = { 0, };
	int retry = 1;
	int ret = -1;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	/*  support above version 2.6.27*/
	if (fd < 0) {
		if (errno == EINVAL) {
			fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0) {
				_E("second chance - socket create error");
				return -1;
			}
		} else {
			_E("socket error");
			return -1;
		}
	}

	saddr.sun_family = AF_UNIX;
	if (pid == AUL_UTIL_PID)
		snprintf(saddr.sun_path, sizeof(saddr.sun_path),
				"/run/amd/%d", uid);
	else
		snprintf(saddr.sun_path, sizeof(saddr.sun_path),
				"/run/user/%d/%d", uid, pid);
 retry_con:
	ret = __connect_client_sock(fd, (struct sockaddr *)&saddr, sizeof(saddr),
			100 * 1000);
	if (ret < -1) {
		_E("maybe peer not launched or peer daed\n");
		if (retry > 0) {
			usleep(100 * 1000);
			retry--;
			goto retry_con;
		}
	}
	if (ret < 0) {
		close(fd);
		return -1;
	}

	__set_sock_option(fd, 1);

	return fd;
}

static int __connect_client_sock(int fd, const struct sockaddr *saptr, socklen_t salen,
		   int nsec)
{
	int flags;
	int ret;
	int error;
	socklen_t len;
	fd_set readfds;
	fd_set writefds;
	struct timeval timeout;

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	error = 0;
	if ((ret = connect(fd, (struct sockaddr *)saptr, salen)) < 0) {
		if (errno != EAGAIN && errno != EINPROGRESS) {
			fcntl(fd, F_SETFL, flags);
			return (-2);
		}
	}

	/* Do whatever we want while the connect is taking place. */
	if (ret == 0)
		goto done;	/* connect completed immediately */

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	writefds = readfds;
	timeout.tv_sec = 0;
	timeout.tv_usec = nsec;

	if ((ret = select(fd + 1, &readfds, &writefds, NULL,
			nsec ? &timeout : NULL)) == 0) {
		close(fd);	/* timeout */
		errno = ETIMEDOUT;
		return (-1);
	}

	if (FD_ISSET(fd, &readfds) || FD_ISSET(fd, &writefds)) {
		len = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return (-1);	/* Solaris pending error */
	} else
		return (-1);	/* select error: sockfd not set*/

 done:
	(void) fcntl(fd, F_SETFL, flags);
	if (error) {
		close(fd);
		errno = error;
		return (-1);
	}
	return (0);
}

static int __send_raw_async_with_fd(int fd, int cmd, unsigned char *kb_data, int datalen, int opt)
{
	int len;
	int sent = 0;
	app_pkt_t *pkt = NULL;

	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + datalen);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}

	pkt->cmd = cmd;
	pkt->len = datalen;
	pkt->opt = opt;

	if (kb_data)
		memcpy(pkt->data, kb_data, pkt->len);

	while (sent != AUL_PKT_HEADER_SIZE + pkt->len) {
		len = send(fd, pkt, AUL_PKT_HEADER_SIZE + pkt->len - sent, 0);
		if (len <= 0) {
			_E("send error fd:%d (errno %d)", fd, errno);
			free(pkt);
			return -ECOMM;
		}
		sent += len;
	}

	free(pkt);

	return 0;
}

API int aul_sock_send_raw_with_fd(int fd, int cmd, unsigned char *kb_data, int datalen, int opt)
{
	int len;
	int res;

	if (kb_data == NULL) {
		_E("keybundle error");
		return -EINVAL;
	}

	_D("fd(%d): cmd(%d)", fd, cmd);

	res = __send_raw_async_with_fd(fd, cmd, kb_data, datalen, opt);
	if (res < 0 || opt & AUL_SOCK_NOREPLY) {
		close(fd);
		return res;
	}

	if (opt & AUL_SOCK_ASYNC)
		return fd;

retry_recv:
	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout : %s", strerror(errno));
			res = -EAGAIN;
		} else if (errno == EINTR) {
			_D("recv : %s", strerror(errno));
			goto retry_recv;
		} else {
			_E("recv error : %s", strerror(errno));
			res = -ECOMM;
		}
	}

	close(fd);

	return res;
}

API int aul_sock_send_bundle_with_fd(int fd, int cmd, bundle *kb, int opt)
{
	bundle_raw *kb_data = NULL;
	int datalen;
	int res;

	if (!kb)
		return -EINVAL;

	res = bundle_encode(kb, &kb_data, &datalen);
	if (res != BUNDLE_ERROR_NONE)
		return -EINVAL;

	res = aul_sock_send_raw_with_fd(fd, cmd, kb_data, datalen, opt | AUL_SOCK_BUNDLE);

	if (kb_data)
		free(kb_data);

	return res;
}

/*
 * @brief	Send data (in raw) to the process with 'pid' via socket
 */
API int aul_sock_send_raw(int pid, uid_t uid, int cmd,
		unsigned char *kb_data, int datalen, int opt)
{
	int fd;

	if (kb_data == NULL) {
		_E("keybundle error");
		return -EINVAL;
	}

	_D("pid(%d): cmd(%d)", pid, cmd);

	fd = __create_client_sock(pid, uid);
	if (fd < 0)
		return -ECOMM;

	return aul_sock_send_raw_with_fd(fd, cmd, kb_data, datalen, opt);
}

API int aul_sock_send_bundle(int pid, uid_t uid, int cmd, bundle *kb, int opt)
{
	bundle_raw *kb_data = NULL;
	int datalen;
	int res;

	if (!kb)
		return -EINVAL;

	res = bundle_encode(kb, &kb_data, &datalen);
	if (res != BUNDLE_ERROR_NONE)
		return -EINVAL;

	res = aul_sock_send_raw(pid, uid, cmd, kb_data, datalen, opt | AUL_SOCK_BUNDLE);

	if (kb_data)
		free(kb_data);

	return res;
}

API app_pkt_t *aul_sock_recv_pkt(int fd, int *clifd, struct ucred *cr)
{
	int len;
	int ret;
	struct sockaddr_un aul_addr = { 0, };
	int sun_size;
	app_pkt_t *pkt = NULL;
	int cl = sizeof(struct ucred);
	unsigned char buf[AUL_SOCK_MAXBUFF];
	int cmd;
	int datalen;
	int opt;

	sun_size = sizeof(struct sockaddr_un);

	if ((*clifd = accept(fd, (struct sockaddr *)&aul_addr,
			     (socklen_t *) &sun_size)) == -1) {
		if (errno != EINTR)
			_E("accept error");
		return NULL;
	}

	if (getsockopt(*clifd, SOL_SOCKET, SO_PEERCRED, cr,
		       (socklen_t *) &cl) < 0) {
		_E("peer information error");
		close(*clifd);
		return NULL;
	}

	__set_sock_option(*clifd, 1);

 retry_recv:
	/* receive header(cmd, datalen) */
	len = recv(*clifd, buf, AUL_PKT_HEADER_SIZE, 0);
	if (len < 0)
		if (errno == EINTR)
			goto retry_recv;

	if (len < AUL_PKT_HEADER_SIZE) {
		_E("recv error");
		close(*clifd);
		return NULL;
	}
	memcpy(&cmd, buf, sizeof(int));
	memcpy(&datalen, buf + sizeof(int), sizeof(int));
	memcpy(&opt, buf + sizeof(int) + sizeof(int), sizeof(int));

	/* allocate for a null byte */
	pkt = (app_pkt_t *)calloc(1, AUL_PKT_HEADER_SIZE + datalen + 1);
	if (pkt == NULL) {
		close(*clifd);
		return NULL;
	}
	pkt->cmd = cmd;
	pkt->len = datalen;
	pkt->opt = opt;

	len = 0;
	while (len != pkt->len) {
		ret = recv(*clifd, pkt->data + len, pkt->len - len, 0);
		if (ret < 0) {
			_E("recv error %d %d", len, pkt->len);
			free(pkt);
			close(*clifd);
			return NULL;
		}
		len += ret;
		_D("recv len %d %d", len, pkt->len);
	}

	return pkt;
}

API int aul_sock_recv_reply_pkt(int fd, app_pkt_t **ret_pkt)
{
	int len;
	int ret;
	int recv_opt;
	app_pkt_t *pkt = NULL;
	unsigned char buf[AUL_SOCK_MAXBUFF];

retry_recv:
	/* receive header(cmd, datalen) */
	len = recv(fd, buf, AUL_PKT_HEADER_SIZE, 0);
	if (len < 0)
		if (errno == EINTR)
			goto retry_recv;

	if (len < AUL_PKT_HEADER_SIZE) {
		_E("recv error");
		close(fd);
		if (len == sizeof(int)) {
			memcpy(&ret, buf, sizeof(int));
			return ret;
		}

		*ret_pkt = NULL;
		return AUL_R_ECOMM;
	}
	memcpy(&cmd, buf, sizeof(int));
	memcpy(&len, buf + sizeof(int), sizeof(int));
	memcpy(&recv_opt, buf + sizeof(int) + sizeof(int), sizeof(int));

	/* allocate for a null byte */
	pkt = (app_pkt_t *)calloc(1, AUL_PKT_HEADER_SIZE + len + 1);
	if (pkt == NULL) {
		close(fd);
		*ret_pkt = NULL;
		return AUL_R_ECOMM;
	}
	pkt->cmd = cmd;
	pkt->len = len;
	pkt->opt = recv_opt;

	len = 0;
	while (len != pkt->len) {
		ret = recv(fd, pkt->data + len, pkt->len - len, 0);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				_E("recv error %s\n", strerror(errno));
				free(pkt);
				close(fd);
				*ret_pkt = NULL;
				return AUL_R_ECOMM;
			}
		}
		len += ret;
		_D("recv len %d %d", len, pkt->len);
	}
	close(fd);

	*ret_pkt = pkt;
	return AUL_R_OK;
}

static int __get_descriptors(struct cmsghdr *cmsg, struct msghdr *msg, int *fds, int maxdesc)
{
	int retnr = 0;
	int nrdesc;
	int payload;
	int *recvdesc;
	int i;

	if (cmsg == NULL || msg == NULL)
		return 0;
	if (cmsg->cmsg_type != SCM_RIGHTS)
		return 0;

	if (msg->msg_controllen > 0) {
		payload = cmsg->cmsg_len - sizeof(*cmsg);
		recvdesc = (int *)CMSG_DATA(cmsg);

		nrdesc = payload / sizeof(int);
		retnr = nrdesc < maxdesc ? nrdesc : maxdesc;
		for (i = 0; i < nrdesc; ++i) {
			if (maxdesc-- > 0)
				*fds++ = *recvdesc++;
			else
				close(*recvdesc++);
		}
	}

	return retnr;
}

static int __recv_message(int sock, struct iovec *vec, int vec_max_size, int *vec_size,
		int *fds, int *nr_fds)
{
	char buff[CMSG_SPACE(sizeof(int) * MAX_NR_OF_DESCRIPTORS) + CMSG_SPACE(50)] = {0};
	struct msghdr msg = {0};
	struct cmsghdr *cmsg = NULL;
	int ret;

	if (vec == NULL || vec_max_size < 1 || vec_size == NULL)
		return -EINVAL;

	msg.msg_iov = vec;
	msg.msg_iovlen = vec_max_size;
	msg.msg_control = buff;
	msg.msg_controllen = sizeof(buff);

	ret = recvmsg(sock, &msg, 0);
	if (ret < 0)
		return -errno;
	*vec_size = msg.msg_iovlen;

	/* get the ANCILLARY data */
	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL) {
		if (nr_fds != NULL)
			*nr_fds = 0;
	} else {
		int iter = 0;
		int fdnum = 0;

		for (; cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg), iter++) {
			switch (cmsg->cmsg_type) {
			case SCM_RIGHTS:
				if (fds != NULL)
					fdnum = __get_descriptors(cmsg, &msg, fds, MAX_NR_OF_DESCRIPTORS);
				if (nr_fds != NULL)
					*nr_fds = fdnum;
				break;
			}
		}
	}

	return ret;
}

int aul_sock_recv_reply_sock_fd(int fd, int *ret_fd, int fd_size)
{
	int fds[2] = {0,};
	char recv_buff[1024];
	struct iovec vec[3];
	int ret = 0;
	int vec_len = 0;
	int fds_len = 0;

	vec[0].iov_base = recv_buff;
	vec[0].iov_len = sizeof(recv_buff);
	ret = __recv_message(fd, vec, 1, &vec_len, fds, &fds_len);
	if (ret < 0) {
		_E("Error[%d]. while receiving message\n", -ret);
		if (fds_len > 0)
			close(fds[0]);

		ret = -ECOMM;
	} else if ((fds_len == fd_size) && (fds_len == 2)) {
		ret_fd[0] = fds[0];
		ret_fd[1] = fds[1];
	} else if ((fds_len == fd_size) && (fds_len == 1)) {
		ret_fd[0] = fds[0];
	} else {
		_E("wrong number of FD recevied. Expected:%d Actual:%d\n", fd_size, fds_len);
		ret = -ECOMM;
	}

	close(fd);
	return ret;
}
