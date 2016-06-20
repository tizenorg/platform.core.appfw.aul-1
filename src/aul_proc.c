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
#include "aul_proc.h"
#include "aul_util.h"

#define MAX_CMD_BUFSZ 1024
#define APP_LABEL_PREFIX "User::App::"
#define BINSH_NAME "/bin/sh"
#define BASH_NAME "/bin/bash"
#define VALGRIND_NAME "/usr/bin/valgrind"
#define OPROFILE_NAME "/usr/bin/oprofile_command"
#define OPTION_VALGRIND_NAME "valgrind"

static int __read_proc(const char *path, char *buf, int size)
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

static int __find_pid_by_appid(const char *dname, const char *appid,
		void *priv, uid_t uid)
{
	int pid = 0;

	if (appid && priv &&
			strncmp(appid, (char *)priv, MAX_LOCAL_BUFSZ-1) == 0) {
		pid = atoi(dname);
		if (pid > 0) {
			if (pid != getpgid(pid))
				pid = 0;
		}
	}

	return pid;
}

API int aul_proc_iter_appid(int (*iterfunc)(const char *dname, const char *appid, void *priv, uid_t uid), void *priv)
{
	DIR *dp;
	struct dirent dentry;
	struct dirent *result = NULL;
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

	while (readdir_r(dp, &dentry, &result) == 0 && result != NULL) {
		if (!isdigit(dentry.d_name[0]))
			continue;

		uid = aul_proc_get_usr_bypid(atoi(dentry.d_name));

		snprintf(buf, sizeof(buf), "/proc/%s/attr/current", dentry.d_name);
		ret = __read_proc(buf, buf, sizeof(buf));
		if (ret <= 0)
			continue;

		p = strstr(buf, APP_LABEL_PREFIX);
		/* not an app */
		if (p == NULL)
			continue;
		p = p + strlen(APP_LABEL_PREFIX);
		pid = iterfunc(dentry.d_name, p, priv, uid);

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

API char *aul_proc_get_cmdline_bypid(int pid)
{
	char buf[MAX_CMD_BUFSZ];
	char *p;
	int ret;
	int len;

	snprintf(buf, sizeof(buf), "/prod/%d/cmdline", pid);
	ret = __read_proc(buf, buf, sizeof(buf));
	if (ret <= 0)
		return NULL;

	/* Support app launched by shell script */
	if (!strncmp(buf, BINSH_NAME, strlen(BINSH_NAME))) {
		return strdup(&buf[strlen(BINSH_NAME) + 1]);
	} else if (!strncmp(buf, BASH_NAME, strlen(BASH_NAME))) {
		len = strlen(BASH_NAME) + 1;
		if (!strncmp(&buf[len], OPROFILE_NAME, strlen(OPROFILE_NAME))) {
			len += strlen(OPROFILE_NAME) + 1;
			if (!strncmp(&buf[len], OPTION_VALGRIND_NAME,
						strlen(OPTION_VALGRIND_NAME))) {
				len += strlen(OPTION_VALGRIND_NAME) + 1;
				return strdup(&buf[len]);
			}
		}
	} else {
		p = strstr(buf, VALGRIND_NAME);
		if (p)
			return strdup(p + strlen(VALGRIND_NAME) + 1);
	}

	return strdup(buf);
}

