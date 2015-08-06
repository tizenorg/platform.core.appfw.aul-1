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

#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <aul.h>
#include <string.h>

#include "amd_config.h"
#include "amd_status.h"
#include "amd_appinfo.h"
#include "aul_util.h"
#include "simple_util.h"
#include "app_sock.h"
#include "menu_db_util.h"
#include "amd_app_group.h"

GSList *app_status_info_list = NULL;

int _status_add_app_info_list(const char *appid, const char *app_path, int pid, int pad_pid, uid_t uid)
{
	GSList *iter;
	GSList *iter_next;
	app_status_info_t *info_t;

	GSLIST_FOREACH_SAFE(app_status_info_list, iter, iter_next) {
		info_t = (app_status_info_t *)iter->data;
		if(pid == info_t->pid) {
			if(uid == info_t->uid)
				return 0;
			else {
				//PID is unique so if it is exist but user value is not correct remove it.
				app_status_info_list = g_slist_remove(app_status_info_list, info_t);
				free(info_t);
				break;
			}
		}
	}

	info_t = malloc(sizeof(app_status_info_t));
	if (info_t == NULL) {
		_E("out of memory");
		return -1;
	}
	strncpy(info_t->appid, appid, MAX_PACKAGE_STR_SIZE-1);
	strncpy(info_t->app_path, app_path, MAX_PACKAGE_APP_PATH_SIZE-1);
	info_t->status = STATUS_LAUNCHING;
	info_t->pid = pid;
	info_t->pad_pid = pad_pid;
	info_t->uid = uid;
	app_status_info_list = g_slist_append(app_status_info_list, info_t);

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;

		SECURE_LOGD(" [%d] : %s, %d, %d", info_t->uid, info_t->appid, info_t->pid, info_t->status);
	}

	return 0;
}

int _status_update_app_info_list(int pid, int status, uid_t uid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;
	bool is_sub_app = true;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if((pid == info_t->pid) && ((info_t->uid == uid) || (info_t->uid == 0))) {
			info_t->status = status;
			is_sub_app = false;
			break;
		}
	}

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;

		//SECURE_LOGD("%s, %d, %d", info_t->appid, info_t->pid, info_t->status);
	}

	if (is_sub_app) {
		app_group_set_status(pid, status);
	}

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
		if((pid == info_t->pid) && ((info_t->uid == uid) || (info_t->uid == 0))) {
			app_status_info_list = g_slist_remove(app_status_info_list, info_t);
			free(info_t);
			break;
		}
	}

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;

		//SECURE_LOGD("%s, %d, %d", info_t->appid, info_t->pid, info_t->status);
	}

	return 0;
}

int _status_get_app_info_status(int pid, uid_t uid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(pid == info_t->pid && uid == info_t->uid) {
			return info_t->status;
		}
	}

	return -1;
}

int _status_app_is_running(const char *appid, uid_t uid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if(( strncmp(appid, info_t->appid, MAX_PACKAGE_STR_SIZE) == 0 ) && (info_t->uid == uid)) {
			return info_t->pid;
		}
	}
	return -1;
}

char* _status_app_get_appid_bypid(int pid)
{
	GSList *iter = NULL;
	app_status_info_t *info_t = NULL;

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (app_status_info_t *)iter->data;
		if( pid == info_t->pid ) {
			return info_t->appid;
		}
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

	for (iter = app_status_info_list; iter != NULL; iter = g_slist_next(iter))
	{
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

	len = strlen(buf) + 1;
	pkt = (app_pkt_t *) malloc(sizeof(int) + sizeof(int) + len);
	if (!pkt) {
		_E("malloc fail");
		return 0;
	}

	pkt->cmd = APP_RUNNING_INFO_RESULT;
	pkt->len = len;
	memcpy(pkt->data, buf, len);

	if ((len = send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if (pkt)
		free(pkt);

	close(fd);

	return 0;
}

int _status_app_is_running_v2(const char *appid, uid_t caller_uid)
{
	char *apppath;
	int ret;
	int i = 0;
	struct appinfo *ai;

	if (appid == NULL)
		return -1;

	ai = appinfo_find(caller_uid, appid);
	if (ai == NULL)
		return -1;

	apppath = strdup(appinfo_get_value(ai, AIT_EXEC));
	if (apppath == NULL) {
		_E("out of memory");
		return -1;
	}

	/*truncate apppath if it includes default bundles */
	while (apppath[i] != 0) {
		if (apppath[i] == ' ' || apppath[i] == '\t') {
			apppath[i]='\0';
			break;
		}
		i++;
	}

	ret = __proc_iter_cmdline(NULL, apppath);

	free(apppath);

	return ret;
}

static int __get_pkginfo(const char *dname, const char *cmdline, void *priv,uid_t uid)
{
	app_info_from_db *menu_info;
	char *r_info;
	char *appid;
	char *app_path;

	r_info = (char *)priv;

	if ((menu_info = _get_app_info_from_db_by_apppath_user(cmdline,uid)) == NULL)
		goto out;
	else {
		appid = _get_appid(menu_info);
		if (appid == NULL)
			goto out;
		app_path = _get_app_path(menu_info);
		if (app_path == NULL)
			goto out;
		strncat(r_info, dname, 8);
		strncat(r_info, ":", 1);
		strncat(r_info, _get_appid(menu_info), MAX_PACKAGE_STR_SIZE);
		strncat(r_info, ":", 1);
		strncat(r_info, _get_app_path(menu_info), MAX_PACKAGE_APP_PATH_SIZE);
		strncat(r_info, ";", 1);
	}

 out:
	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);
	return 0;
}

int _status_send_running_appinfo_v2(int fd)
{
	app_pkt_t *pkt = NULL;
	int len;
	char buf[AUL_SOCK_MAXBUFF] = {0 ,};

	__proc_iter_cmdline(__get_pkginfo, buf);
	len = strlen(buf) + 1;

	pkt = (app_pkt_t *) malloc(sizeof(int) + sizeof(int) + len);
	if (!pkt) {
		_E("malloc fail");
		close(fd);
		return 0;
	}

	pkt->cmd = APP_RUNNING_INFO_RESULT;
	pkt->len = len;
	memcpy(pkt->data, buf, len);

	if ((len = send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if(pkt)
		free(pkt);

	close(fd);

	return 0;
}

static int __get_appid_bypid(int pid, char *appid, int len)
{
	char *cmdline;
	app_info_from_db *menu_info;
	uid_t uid;
	cmdline = __proc_get_cmdline_bypid(pid);
	if (cmdline == NULL)
		return -1;

	uid = __proc_get_usr_bypid(pid);
	if (uid == -1) {
		free(cmdline);
		return -1;
	}

	if ((menu_info = _get_app_info_from_db_by_apppath_user(cmdline,uid)) == NULL) {
		free(cmdline);
		return -1;
	} else {
		snprintf(appid, len, "%s", _get_appid(menu_info));
	}

	free(cmdline);
	_free_app_info_from_db(menu_info);

	return 0;
}

int _status_get_appid_bypid(int fd, int pid)
{
	app_pkt_t *pkt = NULL;
	int cmd;
	int len = 0;
	int pgid;
	char appid[MAX_PACKAGE_STR_SIZE] = {0, };

	cmd = APP_GET_APPID_BYPID_ERROR;

	if (__get_appid_bypid(pid, appid, MAX_PACKAGE_STR_SIZE) == 0) {
		SECURE_LOGD("appid for %d is %s", pid, pkt->data);
		len = strlen(appid) + 1;
		cmd = APP_GET_APPID_BYPID_OK;
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
		len = strlen(appid) + 1;
		cmd = APP_GET_APPID_BYPID_OK;
	}

 out:
	pkt = (app_pkt_t *)malloc(sizeof(int) + sizeof(int) + len);
	if (!pkt) {
		_E("malloc fail");
		close(fd);
		return 0;
	}
	pkt->cmd = cmd;
	pkt->len = len;
	memcpy(pkt->data, appid, len);

	if ((len = send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if (pkt)
		free(pkt);

	close(fd);

	return 0;
}
