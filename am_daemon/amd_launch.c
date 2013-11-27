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
#include <sys/prctl.h>
#include <pkgmgr-info.h>
#include <poll.h>
#include <privacy_manager_client.h>

#include "amd_config.h"
#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "app_sock.h"
#include "simple_util.h"
#include "amd_cgutil.h"
#include "launch.h"

#define DAC_ACTIVATE

#include "access_control.h"


#define TERM_WAIT_SEC 3
#define INIT_PID 1

#define AUL_PR_NAME			16
#define PATH_APP_ROOT "/opt/usr/apps"
#define PATH_DATA "/data"
#define SDK_CODE_COVERAGE "CODE_COVERAGE"
#define SDK_DYNAMIC_ANALYSIS "DYNAMIC_ANALYSIS"
#define PATH_DA_SO "/home/developer/sdk_tools/da/da_probe.so"

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


static void _set_sdk_env(const char* appid, char* str) {
	char buf[MAX_LOCAL_BUFSZ];
	int ret;

	_D("key : %s / value : %s", AUL_K_SDK, str);
	/* http://gcc.gnu.org/onlinedocs/gcc/Cross_002dprofiling.html*/
	/* GCOV_PREFIX contains the prefix to add to the absolute paths in the object file. */
	/*		Prefix can be absolute, or relative. The default is no prefix.  */
	/* GCOV_PREFIX_STRIP indicates the how many initial directory names */
	/*		to stripoff the hardwired absolute paths. Default value is 0. */
	if (strncmp(str, SDK_CODE_COVERAGE, strlen(str)) == 0) {
		snprintf(buf, MAX_LOCAL_BUFSZ, PATH_APP_ROOT"/%s"PATH_DATA, appid);
		ret = setenv("GCOV_PREFIX", buf, 1);
		_D("GCOV_PREFIX : %d", ret);
		ret = setenv("GCOV_PREFIX_STRIP", "4096", 1);
		_D("GCOV_PREFIX_STRIP : %d", ret);
	} else if (strncmp(str, SDK_DYNAMIC_ANALYSIS, strlen(str)) == 0) {
		ret = setenv("LD_PRELOAD", PATH_DA_SO, 1);
		_D("LD_PRELOAD : %d", ret);
	}
}

#define USE_ENGINE(engine) setenv("ELM_ENGINE", engine, 1);

static void _set_env(const char *appid, bundle * kb, const char *hwacc)
{
	const char *str;
	const char **str_array;
	int len;
	int i;

	setenv("PKG_NAME", appid, 1);

	USE_ENGINE("gl")

	str = bundle_get_val(kb, AUL_K_STARTTIME);
	if (str != NULL)
		setenv("APP_START_TIME", str, 1);

	if(bundle_get_type(kb, AUL_K_SDK) & BUNDLE_TYPE_ARRAY) {
		str_array = bundle_get_str_array(kb, AUL_K_SDK, &len);
		if(str_array != NULL) {
			for (i = 0; i < len; i++) {
				_D("index : [%d]", i);
				_set_sdk_env(appid, (char *)str_array[i]);
			}
		}
	} else {
		str = bundle_get_val(kb, AUL_K_SDK);
		if(str != NULL) {
			_set_sdk_env(appid, (char *)str);
		}
	}
	if (hwacc != NULL)
		setenv("HWACC", hwacc, 1);
}

static void _prepare_exec(const char *appid, bundle *kb)
{
	const struct appinfo *ai;
	const char *app_path = NULL;
	const char *pkg_type = NULL;
	char *file_name;
	char process_name[AUL_PR_NAME];
	const char *hwacc;
	int ret;

	setsid();

	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);

	ai = appinfo_find(_laf, appid);

	app_path = appinfo_get_value(ai, AIT_EXEC);
	pkg_type = appinfo_get_value(ai, AIT_TYPE);
	hwacc = appinfo_get_value(ai, AIT_HWACC);

	/* SET PRIVILEGES*/
	 _D("appid : %s / pkg_type : %s / app_path : %s ", appid, pkg_type, app_path);
	if ((ret = __set_access(appid, pkg_type, app_path)) < 0) {
		 _D("fail to set privileges - check your package's credential : %d\n", ret);
		return;
	}

	/* SET DUMPABLE - for coredump*/
	prctl(PR_SET_DUMPABLE, 1);

	/* SET PROCESS NAME*/
	if (app_path == NULL) {
		_D("app_path should not be NULL - check menu db");
		return;
	}
	file_name = strrchr(app_path, '/') + 1;
	if (file_name == NULL) {
		_D("can't locate file name to execute");
		return;
	}
	memset(process_name, '\0', AUL_PR_NAME);
	snprintf(process_name, AUL_PR_NAME, "%s", file_name);
	prctl(PR_SET_NAME, process_name);

	/* SET ENVIROMENT*/
	_set_env(appid, kb, hwacc);

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
		_prepare_exec(group, kb);
		execv(b_argv[0], b_argv);
	}

	if (b) {
		_prepare_exec(group, kb);
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

int _start_srv(const struct appinfo *ai, bundle *kb)
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
	     __app_send_raw_with_delay_reply(pid, APP_RESUME_BY_PID, (unsigned char *)&dummy,
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
	if ((ret = __app_send_raw_with_delay_reply(pid, cmd, kb_data, datalen)) < 0)
		_E("error request fake launch - error code = %d", ret);
	free(kb_data);
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

static gboolean __au_glib_check(GSource *src)
{
	GSList *fd_list;
	GPollFD *tmp;

	fd_list = src->poll_fds;
	do {
		tmp = (GPollFD *) fd_list->data;
		if ((tmp->revents & (POLLIN | POLLPRI)))
			return TRUE;
		fd_list = fd_list->next;
	} while (fd_list);

	return FALSE;
}

static gboolean __au_glib_dispatch(GSource *src, GSourceFunc callback,
		gpointer data)
{
	callback(data);
	return TRUE;
}

static gboolean __au_glib_prepare(GSource *src, gint *timeout)
{
	return FALSE;
}

static GSourceFuncs funcs = {
	.prepare = __au_glib_prepare,
	.check = __au_glib_check,
	.dispatch = __au_glib_dispatch,
	.finalize = NULL
};

struct reply_info {
	GSource *src;
	GPollFD *gpollfd;
	guint timer_id;
	int clifd;
	int pid;
};

static gboolean __reply_handler(gpointer data)
{
	struct reply_info *r_info = (struct reply_info *) data;;
	int fd = r_info->gpollfd->fd;
	int len;
	int res = 0;
	int clifd = r_info->clifd;
	int pid = r_info->pid;

	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout : %s", strerror(errno));
			res = -EAGAIN;
		} else {
			_E("recv error : %s", strerror(errno));
			res = -ECOMM;
		}
	}
	close(fd);

	if(res < 0) {
		__real_send(clifd, res);
	} else {
		__real_send(clifd, pid);
	}

	_D("listen fd : %d , send fd : %d, pid : %d", fd, clifd, pid);

	g_source_remove(r_info->timer_id);
	g_source_remove_poll(r_info->src, r_info->gpollfd);
	g_source_destroy(r_info->src);
	g_free(r_info->gpollfd);
	free(r_info);

	return TRUE;
}

static gboolean __recv_timeout_handler(gpointer data)
{
	struct reply_info *r_info = (struct reply_info *) data;
	int fd = r_info->gpollfd->fd;
	int clifd = r_info->clifd;

	__real_send(clifd, -EAGAIN);

	close(fd);

	g_source_remove_poll(r_info->src, r_info->gpollfd);
	g_source_destroy(r_info->src);
	g_free(r_info->gpollfd);
	free(r_info);

	return FALSE;
}

static int __nofork_processing(int cmd, int pid, bundle * kb, int clifd)
{
	int ret = -1;
	int r;
	GPollFD *gpollfd;
	GSource *src;
	struct reply_info *r_info;
	GMainContext *reply_context;

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

	if(ret > 0) {
		src = g_source_new(&funcs, sizeof(GSource));

		gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
		gpollfd->events = POLLIN;
		gpollfd->fd = ret;

		r_info = malloc(sizeof(*r_info));
		r_info->clifd = clifd;
		r_info->pid = pid;
		r_info->src = src;
		r_info->gpollfd = gpollfd;

		_D("listen fd : %d, send fd : %d", ret, clifd);

		r_info->timer_id = g_timeout_add(5200, __recv_timeout_handler, (gpointer) r_info);
		g_source_add_poll(src, gpollfd);
		g_source_set_callback(src, (GSourceFunc) __reply_handler,
				(gpointer) r_info, NULL);
		g_source_set_priority(src, G_PRIORITY_DEFAULT);
		r = g_source_attach(src, NULL);
	}

	return ret;
}


int _start_app(char* appid, bundle* kb, int cmd, int caller_pid, uid_t caller_uid, int fd)
{
	const struct appinfo *ai;
	int ret = -1;
	const char *componet = NULL;
	const char *multiple = NULL;
	const char *app_path = NULL;
	const char *pkg_type = NULL;
	int pid = -1;
	char tmp_pid[MAX_PID_STR_BUFSZ];
	const char *hwacc;
	const char *permission;
	const char *pkgid;
	const char *preload;
	char caller_appid[256];
	pkgmgrinfo_cert_compare_result_type_e compare_result;
	int delay_reply = 0;
	int pad_pid = LAUNCHPAD_PID;
	bool consented = true;

	snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", caller_pid);
	bundle_add(kb, AUL_K_CALLER_PID, tmp_pid);

	if (cmd == APP_START_RES)
		bundle_add(kb, AUL_K_WAIT_RESULT, "1");

	ret = aul_app_get_appid_bypid(caller_pid, caller_appid, sizeof(caller_appid));
	if(ret == 0) {
		bundle_add(kb, AUL_K_CALLER_APPID, caller_appid);
	}

	ai = appinfo_find(_laf, appid);

	if(ai == NULL) {
		__real_send(fd, -1);
		return -1;
	}

	pkgid = appinfo_get_value(ai, AIT_PKGID);

	if(bundle_get_val(kb, AUL_K_PRIVACY_APPID)){
		bundle_del(kb, AUL_K_PRIVACY_APPID);
	} else {
		privacy_manager_client_check_user_consented(pkgid, &consented);

		_D("consented : %d", consented);

		if(consented == false && bundle_get_val(kb, AUL_K_SDK) == NULL) {
			_D("appid : %s", appid);
			bundle_add(kb, AUL_K_PRIVACY_APPID, appid);
			appid = PRIVACY_POPUP;
			bundle_del(kb, AUL_K_PKG_NAME);
			bundle_add(kb, AUL_K_PKG_NAME, appid);
			ai = appinfo_find(_laf, appid);
		}
	}

	componet = appinfo_get_value(ai, AIT_COMP);
	app_path = appinfo_get_value(ai, AIT_EXEC);
	pkg_type = appinfo_get_value(ai, AIT_TYPE);
	permission = appinfo_get_value(ai, AIT_PERM);
	pkgid = appinfo_get_value(ai, AIT_PKGID);

	if(permission && strncmp(permission, "signature", 9) == 0 ) {
		if(caller_uid != 0 && (cmd == APP_START || cmd == APP_START_RES)){
			const struct appinfo *caller_ai;
			caller_ai = appinfo_find(_laf, caller_appid);
			preload = appinfo_get_value(caller_ai, AIT_PRELOAD);
			if( preload && strncmp(preload, "true", 4) != 0 ) {
				pkgmgrinfo_pkginfo_compare_app_cert_info(caller_appid, appid, &compare_result);
				if(compare_result != PMINFO_CERT_COMPARE_MATCH) {
					pid = -EILLEGALACCESS;
					__real_send(fd, pid);
					return pid;
				}
			}
		}
	}

	pkgmgrinfo_client_request_enable_external_pkg(pkgid);

	if (componet && strncmp(componet, "ui", 2) == 0) {
		multiple = appinfo_get_value(ai, AIT_MULTI);
		if (!multiple || strncmp(multiple, "false", 5) == 0) {
			pid = _status_app_is_running_v2(appid);
		}

		if (pid > 0) {
			if (_status_get_app_info_status(pid) == STATUS_DYING) {
				pid = -ETERMINATING;
			} else if (caller_pid == pid) {
				SECURE_LOGD("caller process & callee process is same.[%s:%d]", appid, pid);
				pid = -ELOCALLAUNCH_ID;
			} else {
				if ((ret = __nofork_processing(cmd, pid, kb, fd)) < 0) {
					pid = ret;
				} else {
					delay_reply = 1;
				}
			}
		} else if (cmd != APP_RESUME) {
			hwacc = appinfo_get_value(ai, AIT_HWACC);
			bundle_add(kb, AUL_K_HWACC, hwacc);
			bundle_add(kb, AUL_K_EXEC, app_path);
			bundle_add(kb, AUL_K_PACKAGETYPE, pkg_type);
			if(bundle_get_type(kb, AUL_K_SDK) != BUNDLE_TYPE_NONE) {
				pad_pid = DEBUG_LAUNCHPAD_PID;		
			} else if(strncmp(pkg_type, "wgt", 3) == 0) {
				pad_pid = WEB_LAUNCHPAD_PID;
			}
			pid = app_send_cmd(pad_pid, cmd, kb);
			if(pid == -3) {
				pid = -ENOLAUNCHPAD;
			}
			//_add_cgroup(_lcg, appid, pid);
		}
	} else if (componet && strncmp(componet, "svc", 3) == 0) {
		pid = _status_app_is_running_v2(appid);
		if (pid > 0) {
			if ((ret = __nofork_processing(cmd, pid, kb, fd)) < 0) {
				pid = ret;
			}
		} else if (cmd != APP_RESUME) {
			pid = service_start(_lcg, appid, app_path, kb);
		}
	} else {
		_E("unkown application");
	}

	if(!delay_reply)
		__real_send(fd, pid);

	if(pid > 0) {
		_status_add_app_info_list(appid, app_path, pid, pad_pid);
		ret = ac_server_check_launch_privilege(appid, appinfo_get_value(ai, AIT_TYPE), pid);
		return ret != AC_R_ERROR ? pid : -1;
	}

	return pid;
}


int _launch_init(struct amdmgr* amd)
{
	_laf = amd->af;
	_lcg = amd->cg;

	return 0;
}



