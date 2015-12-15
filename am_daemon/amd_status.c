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

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <glib.h>
#include <aul.h>
#include <string.h>
#include <linux/limits.h>

#include <gio/gio.h>

#include "amd_config.h"
#include "amd_status.h"
#include "amd_appinfo.h"
#include "amd_request.h"
#include "aul_util.h"
#include "simple_util.h"
#include "app_sock.h"
#include "menu_db_util.h"
#include "amd_app_group.h"

typedef struct _pkg_status_info_t {
	char *pkgid;
	int status;
	GSList *ui_list;
        GSList *svc_list;
} pkg_status_info_t;

typedef struct _app_status_info_t{
	char *appid;
	char *app_path;
	char *pkgid;
	int status;
	int pid;
	int pad_pid;
	bool is_subapp;
	pkg_status_info_t *pkginfo;
	uid_t uid;
} app_status_info_t;

static GSList *app_status_info_list = NULL;
static GHashTable *pkg_status_info_table = NULL;

static void __add_pkg_info(const char *pkgid, app_status_info_t *appinfo)
{
	pkg_status_info_t *pkginfo = NULL;

	if (pkgid == NULL || appinfo == NULL) {
		_E("empty arguments: %s", pkgid == NULL ? (appinfo == NULL ? "appinfo, pkgid" : "pkgid") : "appinfo");
		return;
	}

	if (pkg_status_info_table == NULL)
		pkg_status_info_table = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

	pkginfo = g_hash_table_lookup(pkg_status_info_table, pkgid);
	if (pkginfo == NULL) {
		pkginfo = (pkg_status_info_t *)malloc(sizeof(pkg_status_info_t));
		if (pkginfo == NULL) {
			_E("failed to allocate memory");
			return;
		}

		memset(pkginfo, 0, sizeof(pkg_status_info_t));
		pkginfo->pkgid = strdup(pkgid);
		if (pkginfo->pkgid == NULL) {
			free(pkginfo);
			_E("failed to allocate memory");
			return;
		}

		g_hash_table_insert(pkg_status_info_table, pkginfo->pkgid, pkginfo);
	}

	pkginfo->status = appinfo->status;
	appinfo->pkginfo = pkginfo;

	if (appinfo->status == STATUS_SERVICE)
		pkginfo->svc_list = g_slist_append(pkginfo->svc_list, appinfo);
	else
		pkginfo->ui_list = g_slist_append(pkginfo->ui_list, appinfo);
}

static int __get_ui_app_status_pkg_info(pkg_status_info_t *pkginfo)
{
	app_status_info_t *appinfo = NULL;
	GSList *iter = NULL;
	int status = STATUS_BG;

	if (pkginfo == NULL)
		return -1;

	iter = pkginfo->ui_list;
	while (iter) {
		appinfo = (app_status_info_t *)iter->data;
		if (appinfo->status != STATUS_BG) {
			status = appinfo->status;
		}

		iter = g_slist_next(iter);
	}

	return status;
}

static int __update_pkg_info(const char *pkgid, app_status_info_t *appinfo)
{
	pkg_status_info_t *pkginfo = NULL;
	int ret = 0;

	if (pkgid == NULL || appinfo == NULL)
		return -1;

	if (pkg_status_info_table == NULL)
		return -1;

	pkginfo = (pkg_status_info_t *)g_hash_table_lookup(pkg_status_info_table, pkgid);
	if (pkginfo == NULL) {
		_E("pkgid(%s) is not on list");
		return -1;
	}

	if (pkginfo->ui_list) {
		ret = __get_ui_app_status_pkg_info(pkginfo);
		if (ret > -1)
			pkginfo->status = ret;
	} else {
		pkginfo->status = STATUS_SERVICE;
	}

	return 0;
}


static void __remove_pkg_info(const char *pkgid, app_status_info_t *appinfo, uid_t caller_uid)
{
	pkg_status_info_t *pkginfo = NULL;
	const struct appinfo *ai = NULL;
	const char *component_type = NULL;

	if (pkgid == NULL || appinfo == NULL) {
		_E("empty arguments: %s", pkgid == NULL ? (appinfo == NULL ? "appinfo, pkgid" : "pkgid") : "appinfo");
		return;
	}

	ai = appinfo_find(caller_uid, appinfo->appid);
	component_type = appinfo_get_value(ai, AIT_COMPTYPE);

	pkginfo = (pkg_status_info_t *)g_hash_table_lookup(pkg_status_info_table, pkgid);
	if (pkginfo == NULL) {
		_E("pkgid(%s) is not on list");
		return;
	}

	if (component_type && strcmp(component_type, APP_TYPE_SERVICE) == 0) {
		if (pkginfo->svc_list) {
			pkginfo->svc_list = g_slist_remove(pkginfo->svc_list, appinfo);
			_D("STATUS_SERVICE : appid(%s)", appinfo->appid);
		}
	} else {
		if (pkginfo->ui_list) {
			pkginfo->ui_list = g_slist_remove(pkginfo->ui_list, appinfo);
			_D("~STATUS_SERVICE : appid(%s)", appinfo->appid);
		}
	}

	if (!pkginfo->svc_list && !pkginfo->ui_list) {
		g_hash_table_remove(pkg_status_info_table, pkgid);
		if (pkginfo->pkgid) {
			free(pkginfo->pkgid);
			pkginfo->pkgid = NULL;
		}
		free(pkginfo);
	}
}

static void __destroy_app_status_info(app_status_info_t *info_t)
{
	if (info_t == NULL)
		return;

	if (info_t->appid) {
		free(info_t->appid);
		info_t->appid = NULL;
	}

	if (info_t->app_path) {
		free(info_t->app_path);
		info_t->app_path = NULL;
	}

	if (info_t->pkgid) {
		free(info_t->pkgid);
		info_t->pkgid = NULL;
	}

	free(info_t);
}

int _status_add_app_info_list(const char *appid, const char *app_path, int pid,
				int pad_pid, bool is_subapp, uid_t uid)
{
	GSList *iter;
	GSList *iter_next;
	app_status_info_t *info_t;
	const struct appinfo *ai;
	const char *component_type = NULL;
	const char *pkgid = NULL;

	if (!appid || !app_path)
		return -1;

	GSLIST_FOREACH_SAFE(app_status_info_list, iter, iter_next) {
		info_t = (app_status_info_t *)iter->data;
		if(pid == info_t->pid) {
			if(uid == info_t->uid)
				return 0;
			else {
				/* PID is unique so if it is exist but user value is not correct remove it. */
				app_status_info_list = g_slist_remove(app_status_info_list, info_t);
				__remove_pkg_info(info_t->pkgid, info_t, uid);
				__destroy_app_status_info(info_t);
				break;
			}
		}
	}

	ai = appinfo_find(uid, appid);

	info_t = malloc(sizeof(app_status_info_t));
	if (info_t == NULL) {
		_E("out of memory");
		return -1;
	}

	memset(info_t, 0, sizeof(app_status_info_t));

	info_t->appid = strdup(appid);
	if (info_t->appid == NULL)
		goto error;

	info_t->app_path = strdup(app_path);
	if (info_t->app_path == NULL)
		goto error;

	component_type = appinfo_get_value(ai, AIT_COMPTYPE);
	if (component_type && strcmp(component_type, APP_TYPE_SERVICE) == 0)
		info_t->status = STATUS_SERVICE;
	else
		info_t->status = STATUS_LAUNCHING;

	pkgid = appinfo_get_value(ai, AIT_PKGID);
	if (pkgid == NULL)
		goto error;

	info_t->pid = pid;
	info_t->pad_pid = pad_pid;
	info_t->is_subapp = is_subapp;
	info_t->uid = uid;
	info_t->pkgid = strdup(pkgid);
	if (info_t->pkgid == NULL)
		goto error;

	app_status_info_list = g_slist_append(app_status_info_list, info_t);
	__add_pkg_info(pkgid, info_t);
	_D("pid(%d) appid(%s) pkgid(%s) comp(%s)", pid, appid, pkgid, component_type);

	return 0;
error:
	__destroy_app_status_info(info_t);

	return -1;
}

int _status_update_app_info_list(int pid, int status, uid_t uid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	_D("pid(%d) status(%d)", pid, status);
	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter)) {
		info_t = (app_status_info_t *)iter->data;
		if ((pid == info_t->pid) && ((info_t->uid == uid) || (info_t->uid == 0))) {
			info_t->status = status;
			__update_pkg_info(info_t->pkgid, info_t);

			_D("pid(%d) appid(%s) pkgid(%s) status(%d)", pid, info_t->appid, info_t->pkgid, info_t->status);
			break;
		}
	}

	app_group_set_status(pid, status, false);

	return 0;
}

int _status_remove_app_info_list_with_uid(uid_t uid)
{
	GSList *iter;
	GSList *iter_next;
	app_status_info_t *info_t;

	GSLIST_FOREACH_SAFE(app_status_info_list, iter, iter_next) {
		info_t = (app_status_info_t *)iter->data;
		if (info_t->uid == uid) {
			app_status_info_list =
				g_slist_remove(app_status_info_list, info_t);
			free(info_t);
		}
	}

	return 0;
}

int _status_remove_app_info_list(int pid, uid_t uid)
{
	GSList *iter;
	GSList *iter_next;
	app_status_info_t *info_t;

	GSLIST_FOREACH_SAFE(app_status_info_list, iter, iter_next) {
		info_t = (app_status_info_t *)iter->data;
		if ((pid == info_t->pid) && ((info_t->uid == uid) || (info_t->uid == 0))) {
			app_status_info_list = g_slist_remove(app_status_info_list, info_t);
			__remove_pkg_info(info_t->pkgid, info_t, uid);
			__destroy_app_status_info(info_t);
			break;
		}
	}

	return 0;
}

int _status_get_app_info_status(int pid, uid_t uid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter)) {
		info_t = (app_status_info_t *)iter->data;
		if (pid == info_t->pid
				&& ((uid == 0) ? true : (uid == info_t->uid)))
			return info_t->status;
	}

	return app_group_get_status(pid);
}

static gint __find_app_bypid(gconstpointer app_data, gconstpointer pid_data)
{
	int pid = GPOINTER_TO_INT(pid_data);
	app_status_info_t *appinfo = (app_status_info_t *)app_data;

	if (appinfo && pid && appinfo->pid == pid)
		return 0;

	return -1;
}

void _status_find_service_apps(int pid, uid_t uid, enum app_status status, void (*send_event_to_svc_core) (int), bool suspend)
{
	GSList *app_list = NULL;
	GSList *svc_list = NULL;
	app_status_info_t *info_t = NULL;
	app_status_info_t *svc_info_t = NULL;
	const struct appinfo *ai = NULL;
	int bg_allowed = 0x00;

	app_list = g_slist_find_custom(app_status_info_list, GINT_TO_POINTER(pid), __find_app_bypid);

	if (!app_list) {
		_E("unable to find app by pid:%d", pid);
		return;
	}

	info_t = (app_status_info_t *)app_list->data;
	if (info_t && info_t->pkginfo && info_t->pkginfo->status == status)
		svc_list = info_t->pkginfo->svc_list;

	while (svc_list) {
		svc_info_t = (app_status_info_t *)svc_list->data;
		if (svc_info_t) {
			ai = appinfo_find(uid, svc_info_t->appid);
			bg_allowed = (int)appinfo_get_value(ai, AIT_BG_CATEGORY);
			if (!bg_allowed) {
				send_event_to_svc_core(svc_info_t->pid);
				/* TODO: APIs should be prepared
				if (suspend)
					_amd_suspend_add_timer(svc_info_t->pid, ai);
				else
					_amd_suspend_remove_timer(svc_info_t->pid);
				*/
			}
		}
		svc_list = g_slist_next(svc_list);
	}
}

void _status_check_service_only(int pid, uid_t uid, void (*send_event_to_svc_core) (int))
{
	GSList *app_list = NULL;
	GSList *ui_list = NULL;
	app_status_info_t *info_t = NULL;
	app_status_info_t *ui_info_t = NULL;
	int ui_cnt = 0;

	app_list = g_slist_find_custom(app_status_info_list, GINT_TO_POINTER(pid), __find_app_bypid);

	if (!app_list) {
		_E("unable to find app by pid:%d", pid);
		return;
	}

	info_t = (app_status_info_t *)app_list->data;
	ui_list = info_t->pkginfo->ui_list;
	while (ui_list) {
		ui_info_t = (app_status_info_t *)ui_list->data;
		if (ui_info_t && _status_app_is_running_v2(ui_info_t->appid, uid) > 0)
			ui_cnt++;
		ui_list = g_slist_next(ui_list);
	}

	if (ui_cnt == 0) {
		const char *appid = NULL;
		const struct appinfo *ai = NULL;
		int bg_allowed = 0x00;

		appid = _status_app_get_appid_bypid(pid);
		if (appid) {
			ai = appinfo_find(uid, appid);
			bg_allowed = (int)appinfo_get_value(ai, AIT_BG_CATEGORY);

			if (!bg_allowed) {
				send_event_to_svc_core(pid);
				/* TODO: APIs should be prepared
				_amd_suspend_add_timer(pid, ai);
				*/
			}
		}
	}
}

int _status_app_is_running(const char *appid, uid_t uid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter)) {
		info_t = (app_status_info_t *)iter->data;
		if ((strncmp(appid, info_t->appid, MAX_PACKAGE_STR_SIZE) == 0)
			&& (info_t->uid == uid) && !info_t->is_subapp)
			return info_t->pid;
	}

	return -1;
}

char* _status_app_get_appid_bypid(int pid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter)) {
		info_t = (app_status_info_t *)iter->data;
		if (pid == info_t->pid)
			return info_t->appid;
	}

	return NULL;
}

int _status_send_running_appinfo(int fd, uid_t uid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;
	app_pkt_t *pkt = NULL;
	int len;
	char tmp_pid[MAX_PID_STR_BUFSZ];
	char buf[AUL_SOCK_MAXBUFF] = {0, };

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter)) {
		info_t = (app_status_info_t *)iter->data;
		if (info_t->uid != uid || app_group_is_sub_app(info_t->pid))
			continue;

		snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", info_t->pid);
		strncat(buf, tmp_pid, MAX_PID_STR_BUFSZ);
		strncat(buf, ":", 1);
		strncat(buf, info_t->appid, MAX_PACKAGE_STR_SIZE);
		strncat(buf, ":", 1);
		strncat(buf, info_t->app_path, MAX_PACKAGE_APP_PATH_SIZE);
		strncat(buf, ";", 1);
	}

	len = strlen(buf);
	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + len);
	if (!pkt) {
		_E("malloc fail");
		return 0;
	}

	pkt->cmd = APP_RUNNING_INFO_RESULT;
	pkt->len = len;
	memcpy(pkt->data, buf, len);

	if ((len = send(fd, pkt, pkt->len + AUL_PKT_HEADER_SIZE, 0)) !=
			pkt->len + AUL_PKT_HEADER_SIZE) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if (pkt)
		free(pkt);

	close(fd);

	return 0;
}

static inline int __find_pid_by_appid(const char *dname, const char *appid,
		void *priv, uid_t uid)
{
	int pid = 0;

	if (strncmp(appid, (char *)priv, MAX_LOCAL_BUFSZ-1) == 0) {
		pid = atoi(dname);
		if (pid != getpgid(pid) || app_group_is_sub_app(pid))
			pid = 0;
	}

	return pid;
}

int _status_app_is_running_v2(const char *appid, uid_t caller_uid)
{
	int ret;
	struct appinfo *ai;

	if (appid == NULL)
		return -1;

	ai = appinfo_find(caller_uid, appid);
	if (ai == NULL)
		return -1;

	ret = __proc_iter_appid(__find_pid_by_appid, (void *)appid);

	return ret;
}

static int __get_appid_bypid(int pid, char *appid, int len)
{
	char *result;

	result = __proc_get_appid_bypid(pid);
	if (result == NULL)
		return -1;

	snprintf(appid, len, "%s", result);
	free(result);

	return 0;
}

int _status_get_appid_bypid(int fd, int pid)
{
	app_pkt_t *pkt = NULL;
	int cmd;
	int len = 0;
	int pgid;
	char appid[MAX_PACKAGE_STR_SIZE] = {0, };

	cmd = APP_GET_INFO_ERROR;

	if (__get_appid_bypid(pid, appid, MAX_PACKAGE_STR_SIZE) == 0) {
		SECURE_LOGD("appid for %d is %s", pid, appid);
		len = strlen(appid);
		cmd = APP_GET_INFO_OK;
		goto out;
	}
	/* support app launched by shell script*/
	_D("second chance");
	pgid = getpgid(pid);
	if (pgid <= 1) {
		close(fd);
		return 0;
	}

	_D("second change pgid = %d, pid = %d", pgid, pid);
	if (__get_appid_bypid(pgid, appid, MAX_PACKAGE_STR_SIZE) == 0) {
		len = strlen(appid);
		cmd = APP_GET_INFO_OK;
	}

 out:
	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + len);
	if (!pkt) {
		_E("malloc fail");
		close(fd);
		return 0;
	}
	pkt->cmd = cmd;
	pkt->len = len;
	memcpy(pkt->data, appid, len);

	if ((len = send(fd, pkt, pkt->len + AUL_PKT_HEADER_SIZE, 0)) !=
			pkt->len + AUL_PKT_HEADER_SIZE) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if (pkt)
		free(pkt);

	close(fd);

	return 0;
}

static int __get_pkgid_bypid(int pid, char *pkgid, int len)
{
	char *appid;
	app_info_from_db *menu_info;
	uid_t uid;
	appid = __proc_get_appid_bypid(pid);
	if (appid == NULL)
		return -1;

	uid = __proc_get_usr_bypid(pid);
	if (uid == -1) {
		free(appid);
		return -1;
	}

	if ((menu_info = _get_app_info_from_db_by_appid_user(appid, uid)) == NULL) {
		free(appid);
		return -1;
	} else {
		snprintf(pkgid, len, "%s", _get_pkgid(menu_info));
	}

	free(appid);
	_free_app_info_from_db(menu_info);

	return 0;
}

int _status_get_pkgid_bypid(int fd, int pid)
{
	app_pkt_t *pkt = NULL;
	int cmd;
	int len = 0;
	int pgid;
	char pkgid[MAX_PACKAGE_STR_SIZE] = {0, };

	cmd = APP_GET_INFO_ERROR;

	if (__get_pkgid_bypid(pid, pkgid, MAX_PACKAGE_STR_SIZE) == 0) {
		SECURE_LOGD("pkgid for %d is %s", pid, pkgid);
		len = strlen(pkgid);
		cmd = APP_GET_INFO_OK;
		goto out;
	}
	/* support app launched by shell script*/
	_D("second chance");
	pgid = getpgid(pid);
	if (pgid <= 1) {
		close(fd);
		return 0;
	}

	_D("second change pgid = %d, pid = %d", pgid, pid);
	if (__get_pkgid_bypid(pgid, pkgid, MAX_PACKAGE_STR_SIZE) == 0) {
		len = strlen(pkgid);
		cmd = APP_GET_INFO_OK;
	}

 out:
	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + len);
	if (!pkt) {
		_E("malloc fail");
		close(fd);
		return 0;
	}
	pkt->cmd = cmd;
	pkt->len = len;
	memcpy(pkt->data, pkgid, len);

	if ((len = send(fd, pkt, pkt->len + AUL_PKT_HEADER_SIZE, 0)) !=
			pkt->len + AUL_PKT_HEADER_SIZE) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if (pkt)
		free(pkt);

	close(fd);

	return 0;
}

static void __socket_monitor_cb(GFileMonitor *monitor, GFile *file,
		GFile *other_file, GFileMonitorEvent event_type,
		gpointer user_data)
{
	char *path;
	char *p;
	int pid;

	if (event_type != G_FILE_MONITOR_EVENT_CREATED)
		return;

	path = g_file_get_path(file);
	p = strrchr(path, '/');
	pid = atoi(p + 1);

	if (pid < 1)
		return;

	_request_reply_for_pending_request(pid);

	g_free(path);
}

int _status_init(void)
{
	char buf[PATH_MAX];
	GFile *file;
	GFileMonitor *monitor;
	GError *err = NULL;

	snprintf(buf, sizeof(buf), "/run/user/%d", getuid());
	file = g_file_new_for_path(buf);
	if (file == NULL)
		return -1;

	monitor = g_file_monitor_directory(file, G_FILE_MONITOR_NONE,
			NULL, &err);
	if (monitor == NULL)
		return -1;

	g_signal_connect(monitor, "changed", G_CALLBACK(__socket_monitor_cb),
			NULL);

	return 0;
}
