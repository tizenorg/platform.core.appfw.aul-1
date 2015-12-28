/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>

#include "aul_api.h"
#include "simple_util.h"
#include "aul_proc.h"

#define BINSH_NAME	"/bin/sh"
#define BINSH_SIZE	7
#define VALGRIND_NAME	"/home/developer/sdk_tools/valgrind/usr/bin/valgrind"
#define VALGRIND_SIZE	51
#define BASH_NAME	"/bin/bash"
#define BASH_SIZE	9
#define OPROFILE_NAME	"/usr/bin/oprofile_command"
#define OPROFILE_SIZE	25
#define OPTION_VALGRIND_NAME	"valgrind"
#define OPTION_VALGRIND_SIZE	8

#define PROC_STAT_GID_POS	5

#define MAX_CMD_BUFSZ 1024
#define APP_LABEL_PREFIX "User::App::"

static inline int __read_proc(const char *path, char *buf, int size);
static inline int __find_pid_by_appid(const char *dname, const char *appid,
		void *priv, uid_t uid);

static inline int __read_proc(const char *path, char *buf, int size)
{
	int fd;
	int ret;

	if (buf == NULL || path == NULL)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return ret;
}

static inline int __find_pid_by_appid(const char *dname, const char *appid,
		void *priv, uid_t uid)
{
	int pid = 0;

	if (strncmp(appid, (char *)priv, MAX_LOCAL_BUFSZ-1) == 0) {
		pid = atoi(dname);
		if (pid != getpgid(pid))
			pid = 0;
	}

	return pid;
}

API int aul_proc_iter_appid(int (*iterfunc)(const char *dname, const char *appid, void *priv, uid_t uid), void *priv)
{
	DIR *dp;
	struct dirent *dentry;
	int pid;
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	char *p;
	uid_t uid;

	dp = opendir("/proc");
	if (dp == NULL)
		return -1;

	if (iterfunc == NULL)
		iterfunc = __find_pid_by_appid;

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		uid = aul_proc_get_usr_bypid(atoi(dentry->d_name));

		snprintf(buf, sizeof(buf), "/proc/%s/attr/current", dentry->d_name);
		ret = __read_proc(buf, buf, sizeof(buf));
		if (ret <= 0)
			continue;

		p = strstr(buf, APP_LABEL_PREFIX);
		/* not an app */
		if (p == NULL)
			continue;
		p = p + strlen(APP_LABEL_PREFIX);
		pid = iterfunc(dentry->d_name, p, priv, uid);

		if (pid > 0) {
			closedir(dp);
			return pid;
		}
	}

	closedir(dp);
	return -1;
}

API uid_t aul_proc_get_usr_bypid(int pid)
{
	char buf[MAX_CMD_BUFSZ];
	int ret;
	uid_t uid;
	struct stat DirStat;
	snprintf(buf, sizeof(buf), "/proc/%d", pid);
	ret = stat(buf, &DirStat);
	if (ret < 0)
		uid = (uid_t)-1;
	else
		uid = DirStat.st_uid;
	return uid;
}

API char *aul_proc_get_appid_bypid(int pid)
{
	char buf[MAX_CMD_BUFSZ];
	char *p;
	int ret;

	snprintf(buf, sizeof(buf), "/proc/%d/attr/current", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return NULL;

	p = strstr(buf, APP_LABEL_PREFIX);
	/* not an app */
	if (p == NULL)
		return NULL;

	p = p + strlen(APP_LABEL_PREFIX);

	return strdup(p);
}
