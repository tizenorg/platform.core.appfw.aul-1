/*
 *  aul
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>, Jaeho Lee <jaeho81.lee@samsung.com>
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
 *
 */


#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/smack.h>
#include <errno.h>
#include <fcntl.h>

#include "app_sock.h"
#include "simple_util.h"

static int __connect_client_sock(int sockfd, const struct sockaddr *saptr, socklen_t salen,
		   int nsec);


static inline void __set_sock_option(int fd, int cli)
{
	int size;
	struct timeval tv = { 3, 200 * 1000 };	/*  3.2 sec */

	size = AUL_SOCK_MAXBUFF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (cli)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/*
 * Settings for naming sockets.
 *
 * The historical implmentation was single user oriented and created
 * the UNIX sockets into the directory /tmp/alaunch. While refactoring
 * for a multi users target, the need was to distinguish the sockets 
 * associated to users.
 *
 * For multi users, implementation expect to be launched by a systemd
 * service with if available the socket already opened. Systemd set the
 * environment variable XDG_RUNTIME_DIR, what is a freedesktop standard.
 * (see http://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html)
 *
 * If the environment variable XDG_RUNTIME_DIR isn't set, the directory
 * /run/user/uid is used were uid is the effective user id of the process.
 *
 * Then for multi users, the socket directory used is either
 * $XDG_RUNTIME_DIR/alaunch or /run/user/uid/alaunch, depending on existing
 * or not environment variable XDG_RUNTIME_DIR.
 */

#if defined(MULTI_USER_SUPPORT)
#   define AUL_SOCK_BASE_ENV_NAME	"XDG_RUNTIME_DIR"
#   define AUL_SOCK_BASE_NOENV_PATTERN	"/run/user/%d"
#   define AUL_SOCK_DIR_LENGTH		200
#   define AUL_SOCK_DIR_PATTERN		"%s/alaunch"
#else
#   define AUL_SOCK_DIR_NAME		"/tmp/alaunch"
#endif
#define AUL_SOCK_NAME_PATTERN		"%s/%s"
#define AUL_SOCK_FLAG_DIR_NAMED		1
#define AUL_SOCK_FLAG_DIR_CREATED	2

/*
 * Returns the socket directory name or NULL in case of error.
 *
 * If 'makedir' isn't zero, the directory of the socket will be created
 * (but it don't fail if error occurs when creating the directory).
 */
char *__compute_socket_directory(int makedir)
{
    static int  flags = 0;

#if !defined(MULTI_USER_SUPPORT)
    static char directory[] = AUL_SOCK_DIR_NAME;
#else
    static char directory[AUL_SOCK_DIR_LENGTH];

    if ( !(flags & AUL_SOCK_FLAG_DIR_NAMED) ) {

	char  failbase[AUL_SOCK_DIR_LENGTH];
	char *base;
	int   length;

	/* compute the base directory */
	base = getenv(AUL_SOCK_BASE_ENV_NAME);
	if (base == NULL) {
	    length = snprintf(failbase, sizeof failbase, 
				AUL_SOCK_BASE_NOENV_PATTERN, (int)geteuid());
	    if (length > 0 && length < sizeof failbase) {
		base = failbase;
	    }
	    else {
		return NULL;
	    }
	}

	/* compute the socket directory */
        length = snprintf(directory, sizeof directory, 
				AUL_SOCK_DIR_PATTERN, base);
	if (length > 0 && length < sizeof directory) {
	    flags = flags | AUL_SOCK_FLAG_DIR_NAMED;
	}
	else {
	    return NULL;
	}
    }
#endif

    /* create the directory if needed */
    if ( makedir && !(flags & AUL_SOCK_FLAG_DIR_CREATED) ) {

	mode_t orig_mask = umask(0);
	(void) mkdir(directory, S_IRWXU | S_IRWXG | S_IRWXO | S_ISVTX);
	umask(orig_mask);
	flags = flags | AUL_SOCK_FLAG_DIR_CREATED;
    }

    return directory;
}

/*
 * Compute in 'name' the socket name for the given 'pid'.
 *
 * If 'makedir' isn't zero, the directory of the socket will be created
 * (but it don't fail if error occurs when creating the directory).
 *
 * Returns 1 if ok or else 0 if error.
 */
int __compute_socket_name_s(char *pid, char *name, size_t size, int makedir)
{
    int ret;
    char *directory = __compute_socket_directory(makedir);
    if (directory == NULL) {
	return 0;
    }
    ret = snprintf( name, size, AUL_SOCK_NAME_PATTERN, directory, pid);
    return ret > 0 && ret < size;
}

/*
 * Compute in 'name' the socket name for the given 'pid'.
 *
 * If 'makedir' isn't zero, the directory of the socket will be created
 * (but it don't fail if error occurs when creating the directory).
 *
 * Returns 1 if ok or else 0 if error.
 */
int __compute_socket_name_i(int pid, char *name, size_t size, int makedir)
{
    char buffer[40]; /* enough for 128 bit integers */
    int  ret;

    ret = snprintf( buffer, sizeof buffer, "%d", pid );
    if ( ret <= 0 || ret >= sizeof buffer) {
	return 0;
    }
    return __compute_socket_name_s( buffer, name, size, makedir);
}



int __create_server_sock(int pid)
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
	if (!__compute_socket_name_i(pid, saddr.sun_path, sizeof saddr.sun_path, 1)) {
	    _E("socket name error");
	    return -1;
	}
	unlink(saddr.sun_path);

	/* labeling to socket for SMACK */
	if(getuid() == 0) {	// this is meaningful iff current user is ROOT
		if(smack_fsetlabel(fd, "@", SMACK_LABEL_IPOUT) != 0) {
			/* in case of unsupported filesystem on 'socket' */
			/* or permission error by using 'emulator', bypass*/
			if((errno != EOPNOTSUPP) && (errno != EPERM)) {
				_E("labeling to socket(IPOUT) error");
				close(fd);
				return -1;
			}
		}
		if(smack_fsetlabel(fd, "*", SMACK_LABEL_IPIN) != 0) {
			/* in case of unsupported filesystem on 'socket' */
			/* or permission error by using 'emulator', bypass*/
			if((errno != EOPNOTSUPP) && (errno != EPERM)) {
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
	if (pid != LAUNCHPAD_PID) {
		int pgid;
		pgid = getpgid(pid);
		if (pgid > 1) {
			if (!__compute_socket_name_i(pgid, p_saddr.sun_path, 
					    sizeof p_saddr.sun_path, 0)) {
			    _E("socket name error");
			    return -1;
			}
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

int __create_client_sock(int pid)
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
	if (!__compute_socket_name_i(pid, saddr.sun_path, sizeof saddr.sun_path, 0)) {
	    _E("socket name error");
	    return -1;
	}

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

/**
 * @brief	Send data (in raw) to the process with 'pid' via socket
 */
int __app_send_raw(int pid, int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	int ret;
	int res = 0;
	app_pkt_t *pkt = NULL;

	if (kb_data == NULL || datalen > AUL_SOCK_MAXBUFF - 8) {
		_E("keybundle error\n");
		return -EINVAL;
	}

	_D("pid(%d) : cmd(%d)", pid, cmd);

	fd = __create_client_sock(pid);
	if (fd < 0)
		return -ECOMM;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, datalen);

	if ((len = send(fd, pkt, datalen + 8, 0)) != datalen + 8) {
		_E("sendto() failed - %d %d (errno %d)", len, datalen + 8, errno);
		if(len > 0) {
			while (len != datalen + 8) {
				ret = send(fd, &pkt->data[len-8], datalen + 8 - len, 0);
				if (ret < 0) {
					_E("second sendto() failed - %d %d (errno %d)", ret, datalen + 8, errno);
					if (errno == EPIPE) {
						_E("pid:%d, fd:%d\n", pid, fd);
					}
					close(fd);
					if (pkt) {
						free(pkt);
						pkt = NULL;
					}
					return -ECOMM;
				}
				len += ret;
				_D("sendto() len - %d %d", len, datalen + 8);
			}
		} else {
			if (errno == EPIPE) {
				_E("pid:%d, fd:%d\n", pid, fd);
			}
			close(fd);
			if (pkt) {
				free(pkt);
				pkt = NULL;
			}
			return -ECOMM;
		}
	}
	if (pkt) {
		free(pkt);
		pkt = NULL;
	}

	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout \n");
			res = -EAGAIN;
		} else {
			_E("recv error\n");
			res = -ECOMM;
		}
	}
	close(fd);

	return res;
}

int __app_send_raw_with_noreply(int pid, int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	int ret;
	int res = 0;
	app_pkt_t *pkt = NULL;

	if (kb_data == NULL || datalen > AUL_SOCK_MAXBUFF - 8) {
		_E("keybundle error\n");
		return -EINVAL;
	}

	_D("pid(%d) : cmd(%d)", pid, cmd);

	fd = __create_client_sock(pid);
	if (fd < 0)
		return -ECOMM;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, datalen);

	if ((len = send(fd, pkt, datalen + 8, 0)) != datalen + 8) {
		_E("sendto() failed - %d %d (errno %d)", len, datalen + 8, errno);
		if(len > 0) {
			while (len != datalen + 8) {
				ret = send(fd, &pkt->data[len-8], datalen + 8 - len, 0);
				if (ret < 0) {
					_E("second sendto() failed - %d %d (errno %d)", ret, datalen + 8, errno);
					if (errno == EPIPE) {
						_E("pid:%d, fd:%d\n", pid, fd);
					}
					close(fd);
					if (pkt) {
						free(pkt);
						pkt = NULL;
					}
					return -ECOMM;
				}
				len += ret;
				_D("sendto() len - %d %d", len, datalen + 8);
			}
		} else {
			if (errno == EPIPE) {
				_E("pid:%d, fd:%d\n", pid, fd);
			}
			close(fd);
			if (pkt) {
				free(pkt);
				pkt = NULL;
			}
			return -ECOMM;
		}
	}
	if (pkt) {
		free(pkt);
		pkt = NULL;
	}

	close(fd);

	return res;
}

app_pkt_t *__app_recv_raw(int fd, int *clifd, struct ucred *cr)
{
	int len;
	int ret;
	struct sockaddr_un aul_addr = { 0, };
	int sun_size;
	app_pkt_t *pkt = NULL;
	int cl = sizeof(struct ucred);

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

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if(pkt == NULL) {
		close(*clifd);
		return NULL;
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	__set_sock_option(*clifd, 1);

 retry_recv:
	/* receive single packet from socket */
	len = recv(*clifd, pkt, AUL_SOCK_MAXBUFF, 0);
	if (len < 0)
		if (errno == EINTR)
			goto retry_recv;

	if (len < 8) {
		_E("recv error %d %d", len, pkt->len);
		free(pkt);
		close(*clifd);
		return NULL;
	}

	while( len != (pkt->len + 8) ) {
		ret = recv(*clifd, &pkt->data[len-8], AUL_SOCK_MAXBUFF, 0);
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

app_pkt_t *__app_send_cmd_with_result(int pid, int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	app_pkt_t *pkt = NULL;

	fd = __create_client_sock(pid);
	if (fd < 0)
		return NULL;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return NULL;
	}
	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	pkt->cmd = cmd;
	pkt->len = datalen;
	if(kb_data) {
		memcpy(pkt->data, kb_data, datalen);
	}

	if ((len = send(fd, pkt, datalen + 8, 0)) != datalen + 8) {
		_E("sendto() failed - %d", len);
		if (errno == EPIPE) {
			_E("pid:%d, fd:%d\n", pid, fd);
		}
		close(fd);

		free(pkt);
		return NULL;
	}

retry_recv:
       /* receive single packet from socket */
	len = recv(fd, pkt, AUL_SOCK_MAXBUFF, 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout \n");
			free(pkt);
			close(fd);
			return NULL;
		} else if (errno == EINTR) {
			goto retry_recv;
		} else {
			_E("recv error %s\n", strerror(errno));
			free(pkt);
			close(fd);
			return NULL;
		}
	} else
		_D("recv result  = %d", len);
	close(fd);

	return pkt;
}


