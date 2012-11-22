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

#include <signal.h>
#include <bundle.h>
#include <aul.h>
#include <glib.h>
#include <app-checker-server.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <app2ext_interface.h>

#include "amd_config.h"
#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "app_sock.h"
#include "simple_util.h"
#include "amd_cgutil.h"


#define TERM_WAIT_SEC 3
#define INIT_PID 1

struct appinfomgr *_laf;
struct cginfo *_lcg;

typedef struct {
	char *pkg_name;		/* package */
	char *app_path;		/* exec */
	char *original_app_path;	/* exec */
	int multiple;		/* x_slp_multiple */
	char *pkg_type;
} app_info_from_pkgmgr;

static GList *_kill_list;

struct ktimer {
	pid_t pid;
	char *group;
	guint tid; /* timer ID */
	struct cginfo *cg;
};

static void _prepare_exec(void)
{
	setsid();

	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);

	/* TODO: do security job */
	/* TODO: setuid */
}

static int _add_cgroup(struct cginfo *cg, const char *group, int pid)
{
	int r;

	r = cgutil_exist_group(cg, CTRL_MGR, group);
	if (r == -1) {
		_E("exist check error: %s", strerror(errno));
		return -1;
	}

	if (r == 0) { /* not exist */
		r = cgutil_create_group(cg, CTRL_MGR, group);
		if (r == -1) {
			_E("create group error");
			return -1;
		}
	}

	r = cgutil_group_add_pid(cg, CTRL_MGR, group, pid);
	if (r == -1) {
		_E("add pid to group error");
		cgutil_remove_group(cg, CTRL_MGR, group);
		return -1;
	}

	return 0;
}

static char **__create_argc_argv(bundle * kb, int *margc)
{
	char **argv;
	int argc;

	argc = bundle_export_to_argv(kb, &argv);

	*margc = argc;
	return argv;
}
static void _do_exec(struct cginfo *cg, const char *cmd, const char *group, bundle *kb)
{
	gchar **argv;
	gint argc;
	char **b_argv;
	int b_argc;
	gboolean b;
	int r;

	r = _add_cgroup(cg, group, getpid());
	if (r == -1)
		return;

	b = g_shell_parse_argv(cmd, &argc, &argv, NULL);

	if (kb) {
		b_argv = __create_argc_argv(kb, &b_argc);
		b_argv[0] = strdup(argv[0]);
		_prepare_exec();
		execv(b_argv[0], b_argv);
	}

	if (b) {
		_prepare_exec();
		execv(argv[0], argv);
	}

	_E("exec error: %s", strerror(errno));
	g_strfreev(argv);
}

int service_start(struct cginfo *cg, const char *group, const char *cmd, bundle *kb)
{
	int r;
	pid_t p;

	if (!cg || !group || !*group || !cmd || !*cmd) {
		errno = EINVAL;
		_E("service start: %s", strerror(errno));
		return -1;
	}

	p = fork();
	switch (p) {
	case 0: /* child process */
		_do_exec(cg, cmd, group, kb);
		/* exec error */
		exit(0);
		break;
	case -1:
		_E("service start: fork: %s", strerror(errno));
		r = -1;
		break;
	default: /* parent process */
		_D("child process: %d", p);
		r = p;
		break;
	}

	return r;
}

int _start_srv(struct appinfo *ai, bundle *kb)
{
	int r;
	const char *group;
	const char *cmd;

	group = appinfo_get_filename(ai);

	cmd = appinfo_get_value(ai, AIT_EXEC);
	if (!cmd) {
		_E("start service: '%s' has no exec", group);
		return -1;
	}

	r = service_start(_lcg, group, cmd, kb);
	if (r == -1) {
		_E("start service: '%s': failed", group);
		return -1;
	}

	return 0;
}

static void _free_kt(struct ktimer *kt)
{
	if (!kt)
		return;

	cgutil_unref(&kt->cg);
	free(kt->group);
	free(kt);
}

static void _kill_pid(struct cginfo *cg, const char *group, pid_t pid)
{
	int r;

	if (pid <= INIT_PID) /* block sending to all process or init */
		return;

	r = cgutil_exist_group(cg, CTRL_MGR, group);
	if (r == -1) {
		_E("send SIGKILL: exist: %s", strerror(errno));
		return;
	}
	if (r == 0) {
		_D("send SIGKILL: '%s' not exist", group);
		return;
	}

	/* TODO: check pid exist in group */

	r = kill(pid, 0);
	if (r == -1) {
		_D("send SIGKILL: pid %d not exist", pid);
		return;
	}

	r = kill(pid, SIGKILL);
	if (r == -1)
		_E("send SIGKILL: %s", strerror(errno));
}

static gboolean _ktimer_cb(gpointer data)
{
	struct ktimer *kt = data;

	_kill_pid(kt->cg, kt->group, kt->pid);
	_kill_list = g_list_remove(_kill_list, kt);
	_free_kt(kt);

	return FALSE;
}

static void _add_list(struct cginfo *cg, const char *group, pid_t pid)
{
	struct ktimer *kt;

	kt = calloc(1, sizeof(*kt));
	if (!kt)
		return;

	kt->pid = pid;
	kt->group = strdup(group);
	if (!kt->group) {
		free(kt);
		return;
	}

	kt->cg = cgutil_ref(cg);
	kt->tid = g_timeout_add_seconds(TERM_WAIT_SEC, _ktimer_cb, kt);

	_kill_list = g_list_append(_kill_list, kt);
}

static inline void _del_list(GList *l)
{
	struct ktimer *kt;

	if (!l)
		return;

	kt = l->data;

	g_source_remove(kt->tid);
	_free_kt(kt);
	_kill_list = g_list_delete_link(_kill_list, l);
}

static int _kill_pid_cb(void *user_data, const char *group, pid_t pid)
{
	int r;

	if (pid <= INIT_PID) /* block sending to all process or init */
		return 0;

	r = kill(pid, SIGTERM);
	if (r == -1)
		_E("send SIGTERM: %s", strerror(errno));

	_add_list(user_data, group, pid);

	return 0;
}

int service_stop(struct cginfo *cg, const char *group)
{
	if (!cg || !group || !*group) {
		errno = EINVAL;
		return -1;
	}

	return cgutil_group_foreach_pid(cg, CTRL_MGR, FILENAME(group),
			_kill_pid_cb, cg);
}

void service_release(const char *group)
{
	GList *l;
	GList *d;

	if (!group || !*group)
		return;

	group = FILENAME(group);

	d = NULL;
	for (l = _kill_list; l; l = g_list_next(l)) {
		struct ktimer *k = l->data;

		_del_list(d);

		if (k->group && !strcmp(k->group, group))
			d = l;
	}

	_del_list(d);
}

int _send_to_sigkill(int pid)
{
	int pgid;

	pgid = getpgid(pid);
	if (pgid <= 1)
		return -1;

	if (killpg(pgid, SIGKILL) < 0)
		return -1;

	return 0;
}
int _resume_app(int pid)
{
	int dummy;
	int ret;
	if ((ret =
	     __app_send_raw(pid, APP_RESUME_BY_PID, (unsigned char *)&dummy,
			    sizeof(int))) < 0) {
		if (ret == -EAGAIN)
			_E("resume packet timeout error");
		else {
			_E("raise failed - %d resume fail\n", pid);
			_E("we will term the app - %d\n", pid);
			_send_to_sigkill(pid);
			ret = -1;
		}
	}
	_D("resume done\n");
	return ret;
}

int _term_app(int pid)
{
	int dummy;
	if (__app_send_raw
	    (pid, APP_TERM_BY_PID, (unsigned char *)&dummy, sizeof(int)) < 0) {
		_D("terminate packet send error - use SIGKILL");
		if (_send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d\n", pid);
			return -1;
		}
	}
	_D("term done\n");
	return 0;
}

int _fake_launch_app(int cmd, int pid, bundle * kb)
{
	int datalen;
	int ret;
	bundle_raw *kb_data;

	bundle_encode(kb, &kb_data, &datalen);
	if ((ret = __app_send_raw(pid, cmd, kb_data, datalen)) < 0)
		_E("error request fake launch - error code = %d", ret);
	free(kb_data);
	return ret;
}

static int __nofork_processing(int cmd, int pid, bundle * kb)
{
	int ret = -1;
	switch (cmd) {
	case APP_OPEN:
	case APP_RESUME:
		_D("resume app's pid : %d\n", pid);
		if ((ret = _resume_app(pid)) < 0)
			_E("__resume_app failed. error code = %d", ret);
		_D("resume app done");
		break;

	case APP_START:
	case APP_START_RES:
		_D("fake launch pid : %d\n", pid);
		if ((ret = _fake_launch_app(cmd, pid, kb)) < 0)
			_E("fake_launch failed. error code = %d", ret);
		_D("fake launch done");
		break;
	}
	return ret;
}

static void __real_send(int clifd, int ret)
{
	if (send(clifd, &ret, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
		}
		_E("send fail to client");
	}

	close(clifd);
}

int __sat_ui_launch(char* appid, bundle* kb, int cmd, int caller_pid, int fd)
{
	int ret = -1;
	char *app_path = "/usr/apps/org.tizen.sat-ui/bin/sat-ui KEY_EXEC_TYPE 0";
	int pid = -1;
	char tmp_pid[MAX_PID_STR_BUFSZ];

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", caller_pid);
	bundle_add(kb, AUL_K_CALLER_PID, tmp_pid);

	pid = _status_app_is_running(appid);

	if (pid > 0) {
		if (caller_pid == pid) {
			_D("caller process & callee process is same.[%s:%d]", appid, pid);
			pid = -ELOCALLAUNCH_ID;
		} else if ((ret = __nofork_processing(cmd, pid, kb)) < 0) {
			pid = ret;
		}
	} else if (cmd != APP_RESUME) {
		bundle_add(kb, AUL_K_EXEC, app_path);
		bundle_add(kb, AUL_K_PACKAGETYPE, "rpm");
		pid = app_send_cmd(LAUNCHPAD_PID, cmd, kb);
	}

	__real_send(fd, pid);

	if(pid > 0) {
		_status_add_app_info_list(appid, app_path, pid);
		ac_server_check_launch_privilege(appid, "rpm", pid);
	}

	return pid;
}

int _start_app(char* appid, bundle* kb, int cmd, int caller_pid, int fd)
{
	struct appinfo *ai;
	int ret = -1;
	char *componet = NULL;
	char *multiple = NULL;
	char *app_path = NULL;
	int pid = -1;
	char tmp_pid[MAX_PID_STR_BUFSZ];

	int location = -1;
	app2ext_handle *app2_handle = NULL;

	if(strncmp(appid, "org.tizen.sat-ui", 18) == 0) {
		pid = __sat_ui_launch(appid, kb, cmd, caller_pid, fd);
		return pid;
	}

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", caller_pid);
	bundle_add(kb, AUL_K_CALLER_PID, tmp_pid);

	if (cmd == APP_START_RES)
		bundle_add(kb, AUL_K_WAIT_RESULT, "1");

	ai = appinfo_find(_laf, appid);

	componet = appinfo_get_value(ai, AIT_COMP);
	app_path = appinfo_get_value(ai, AIT_EXEC);
	if (componet && strncmp(componet, "ui", 2) == 0) {
		multiple = appinfo_get_value(ai, AIT_MULTI);
		if (!multiple || strncmp(multiple, "false", 5) == 0) {
			pid = _status_app_is_running(appid);
		}

		if (pid > 0) {
			if (caller_pid == pid) {
				_D("caller process & callee process is same.[%s:%d]", appid, pid);
				pid = -ELOCALLAUNCH_ID;
			} else if ((ret = __nofork_processing(cmd, pid, kb)) < 0) {
				pid = ret;
			}
		} else if (cmd != APP_RESUME) {
			bundle_add(kb, AUL_K_EXEC, app_path);
			bundle_add(kb, AUL_K_PACKAGETYPE, appinfo_get_value(ai, AIT_TYPE));
			pid = app_send_cmd(LAUNCHPAD_PID, cmd, kb);
			//_add_cgroup(_lcg, appid, pid);
		}
	} else if (componet && strncmp(componet, "svc", 3) == 0) {
		pid = _status_app_is_running(appid);
		if (pid > 0) {
			if ((ret = __nofork_processing(cmd, pid, kb)) < 0) {
				pid = ret;
			}
		} else if (cmd != APP_RESUME) {
			pid = service_start(_lcg, appid, app_path, kb);
		}
	} else {
		_E("unkown application");
	}

	location = app2ext_get_app_location(appid);
	if (location == APP2EXT_SD_CARD)
	{
		app2_handle = app2ext_init(APP2EXT_SD_CARD);
		if (app2_handle == NULL) {
			_E("app2_handle : app2ext init failed\n");
			return -1;
		}

		ret = app2_handle->interface.enable(appid);
		if (ret) {
			_E("app2_handle : app enable API fail Reason %d", ret);
		}

		app2ext_deinit(app2_handle);
	}

	__real_send(fd, pid);

	if(pid > 0) {
		_status_add_app_info_list(appid, app_path, pid);
		ac_server_check_launch_privilege(appid, appinfo_get_value(ai, AIT_TYPE), pid);
	}

	return pid;
}


int _launch_init(struct amdmgr* amd)
{
	_laf = amd->af;
	_lcg = amd->cg;

	return 0;
}



