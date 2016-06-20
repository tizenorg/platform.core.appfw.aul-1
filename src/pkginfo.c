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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <bundle_internal.h>

#include "aul.h"
#include "aul_api.h"
#include "menu_db_util.h"
#include "aul_sock.h"
#include "aul_util.h"
#include "aul_proc.h"
#include "aul_error.h"

#define REGULAR_UID_MIN 5000

typedef struct _internal_param_t {
	aul_app_info_iter_fn enum_fn;
	void *user_param;
} internal_param_t;

static const char *__appid = NULL;
static const char *__pkgid = NULL;
static const char *__root_path = NULL;

API int aul_app_get_pid(const char *appid)
{
	return aul_app_get_pid_for_uid(appid, getuid());
}

API int aul_app_get_pid_for_uid(const char *appid, uid_t uid)
{
	int ret = 0;

	if (appid == NULL)
		return -1;

	ret = aul_sock_send_raw(AUL_UTIL_PID, uid, APP_GET_PID,
			(unsigned char *)appid, strlen(appid), AUL_SOCK_NONE);

	return ret;
}

API int aul_app_is_running(const char *appid)
{
	return aul_app_is_running_for_uid(appid, getuid());
}

API int aul_app_is_running_for_uid(const char *appid, uid_t uid)
{
	int ret = 0;

	if (appid == NULL)
		return 0;

	ret = aul_sock_send_raw(AUL_UTIL_PID, uid, APP_IS_RUNNING,
			(unsigned char*)appid, strlen(appid), AUL_SOCK_NONE);

	if (ret > 0)
		return true;

	return 0;
}

API int aul_app_get_running_app_info(aul_app_info_iter_fn enum_fn,
					void *user_param)
{
	return aul_app_get_running_app_info_for_uid(enum_fn, user_param, getuid());;
}

API int aul_app_get_running_app_info_for_uid(aul_app_info_iter_fn enum_fn,
					void *user_param, uid_t uid)
{
	app_pkt_t *pkt = NULL;
	char *saveptr1, *saveptr2;
	char *token;
	char *pkt_data;
	aul_app_info info;
	int ret;
	int fd;

	memset(&info, 0, sizeof(info));
	if (enum_fn == NULL)
		return AUL_R_EINVAL;

	fd = aul_sock_send_raw(AUL_UTIL_PID, uid, APP_RUNNING_INFO, NULL, 0, AUL_SOCK_ASYNC);
	if (fd < 0)
		return aul_error_convert(fd);

	ret = aul_sock_recv_reply_pkt(fd, &pkt);
	if (ret < 0)
		return aul_error_convert(ret);
	else if (pkt == NULL)
		return AUL_R_ECOMM;

	for (pkt_data = (char *)pkt->data; ; pkt_data = NULL) {
		token = strtok_r(pkt_data, ";", &saveptr1);
		if (token == NULL)
			break;
		info.pid = atoi(strtok_r(token, ":", &saveptr2));
		info.appid = strtok_r(NULL, ":", &saveptr2);
		info.app_path = strtok_r(NULL, ":", &saveptr2);
		info.pkgid = strtok_r(NULL, ":", &saveptr2);
		info.status = atoi(strtok_r(NULL, ":", &saveptr2));
		info.is_sub_app = atoi(strtok_r(NULL, ":", &saveptr2));
		info.pkg_name = strdup(info.appid);

		enum_fn(&info, user_param);
		free(info.pkg_name);
	}

	free(pkt);

	return AUL_R_OK;
}

API int aul_app_get_all_running_app_info(aul_app_info_iter_fn enum_fn,
					void *user_param)
{
	return aul_app_get_all_running_app_info_for_uid(enum_fn, user_param, getuid());
}

API int aul_app_get_all_running_app_info_for_uid(aul_app_info_iter_fn enum_fn,
					void *user_param, uid_t uid)
{
	app_pkt_t *pkt = NULL;
	char *saveptr1;
	char *saveptr2;
	char *token;
	char *pkt_data;
	aul_app_info info;
	int ret;
	int fd;

	memset(&info, 0, sizeof(info));
	if (enum_fn == NULL)
		return AUL_R_EINVAL;

	fd = aul_sock_send_raw(AUL_UTIL_PID, uid, APP_ALL_RUNNING_INFO, NULL, 0, AUL_SOCK_ASYNC);
	if (fd < 0)
		return aul_error_convert(fd);

	ret = aul_sock_recv_reply_pkt(fd, &pkt);
	if (ret < 0)
		return aul_error_convert(ret);
	else if (pkt == NULL)
		return AUL_R_ECOMM;

	for (pkt_data = (char *)pkt->data; ; pkt_data = NULL) {
		token = strtok_r(pkt_data, ";", &saveptr1);
		if (token == NULL)
			break;
		info.pid = atoi(strtok_r(token, ":", &saveptr2));
		info.appid = strtok_r(NULL, ":", &saveptr2);
		info.app_path = strtok_r(NULL, ":", &saveptr2);
		info.pkgid = strtok_r(NULL, ":", &saveptr2);
		info.status = atoi(strtok_r(NULL, ":", &saveptr2));
		info.is_sub_app = atoi(strtok_r(NULL, ":", &saveptr2));
		info.pkg_name = strdup(info.appid);

		enum_fn(&info, user_param);
		free(info.pkg_name);
	}

	free(pkt);

	return AUL_R_OK;
}

API void aul_set_preinit_appid(const char *appid)
{
	__appid = appid;
}

API void aul_set_preinit_pkgid(const char *pkgid)
{
	__pkgid = pkgid;
}

API void aul_set_preinit_root_path(const char *root_path)
{
	__root_path = root_path;
}

API const char *aul_get_preinit_root_path(void)
{
	const char *root_path;

	root_path = getenv("AUL_ROOT_PATH");
	if (root_path) {
		if (__root_path == NULL)
			__root_path = strdup(root_path);
		unsetenv("AUL_ROOT_PATH");
	}

	return __root_path;
}

static int __get_info_bypid(int pid, char *buf, int len, int cmd, uid_t uid)
{
	char *cmdline;
	app_info_from_db *menu_info;

	cmdline = aul_proc_get_cmdline_bypid(pid);
	if (cmdline == NULL)
		return -1;

	menu_info = _get_app_info_from_db_by_app_path_user(cmdline, uid);
	if (menu_info == NULL) {
		free(cmdline);
		return -1;
	}

	if (cmd == APP_GET_APPID_BYPID)
		snprintf(buf, len, "%s", _get_appid(menu_info));
	else
		snprintf(buf, len, "%s", _get_pkgid(menu_info));

	_free_app_info_from_db(menu_info);
	free(cmdline);

	return 0;
}

static int __app_get_info_bypid(int pid, char *buf, int len, int cmd, uid_t uid,
		int caller_pid)
{
	app_pkt_t *pkt = NULL;
	int fd;
	int ret;
	int pgid;

	if (pid != caller_pid) {
		uid = aul_proc_get_usr_bypid(pid);
		if (uid < REGULAR_UID_MIN)
			return AUL_R_ERROR;
	}

	fd = aul_sock_send_raw(AUL_UTIL_PID, uid, cmd, (unsigned char *)&pid,
			sizeof(pid), AUL_SOCK_ASYNC);
	if (fd <= 0)
		return AUL_R_ERROR;

	ret = aul_sock_recv_reply_pkt(fd, &pkt);
	if (ret < 0 || pkt == NULL)
		return AUL_R_ERROR;

	if (pkt->cmd == APP_GET_INFO_OK) {
		snprintf(buf, len, "%s", pkt->data);
		free(pkt);
		return AUL_R_OK;
	}

	/* fallback (for debugging) */
	if (getpid() == pid || uid >= REGULAR_UID_MIN) {
		ret = __get_info_bypid(pid, buf, len, cmd, uid);
		if (ret == 0)
			return AUL_R_OK;

		pgid = getpgid(pid);
		if (pgid <= 1)
			return AUL_R_ERROR;

		_D("second chance pgid = %d, pid = %d", pgid, pid);
		return __get_info_bypid(pgid, buf, len, cmd, uid);
	}

	return AUL_R_ERROR;
}

API int aul_app_get_pkgname_bypid(int pid, char *pkgname, int len)
{
	return aul_app_get_appid_bypid(pid, pkgname, len);
}

API int aul_app_get_appid_bypid_for_uid(int pid, char *appid, int len,
		uid_t uid)
{
	int cmd = APP_GET_APPID_BYPID;
	int caller_pid = getpid();

	if (pid <= 0 || appid == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	if (caller_pid == pid && __appid) {
		snprintf(appid, len, "%s", __appid);
		return AUL_R_OK;
	}

	return __app_get_info_bypid(pid, appid, len, cmd, uid, caller_pid);
}

API int aul_app_get_appid_bypid(int pid, char *appid, int len)
{
	return aul_app_get_appid_bypid_for_uid(pid, appid, len, getuid());
}

API int aul_app_get_pkgid_bypid_for_uid(int pid, char *pkgid, int len, uid_t uid)
{
	int cmd = APP_GET_PKGID_BYPID;
	int caller_pid = getpid();

	if (pid <= 0 || pkgid == NULL) {
		_E("Invalid parameter");
		return AUL_R_EINVAL;
	}

	if (pid == caller_pid && __pkgid) {
		snprintf(pkgid, len, "%s", __pkgid);
		return AUL_R_OK;
	}

	return __app_get_info_bypid(pid, pkgid, len, cmd, uid, caller_pid);
}

API int aul_app_get_pkgid_bypid(int pid, char *pkgid, int len)
{
	return aul_app_get_pkgid_bypid_for_uid(pid, pkgid, len, getuid());
}

API int aul_delete_rua_history(bundle *b)
{
	int ret;
	bundle_raw *br = NULL;
	int datalen = 0;

	/* b can be NULL if b is NULL delete all rua history */
	if (b != NULL)
		bundle_encode(b, &br, &datalen);

	ret = aul_sock_send_raw(AUL_UTIL_PID, getuid(),
			APP_REMOVE_HISTORY, br, datalen, AUL_SOCK_NONE);

	if (br != NULL)
		free(br);

	return ret;
}

API int aul_set_default_app_by_operation(bundle *b)
{
	int ret;

	if (b == NULL)
		return AUL_R_EINVAL;

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(),
			APP_SET_APP_CONTROL_DEFAULT_APP, b, AUL_SOCK_NONE);
	if (ret != 0) {
		if (ret == -EILLEGALACCESS)
			return AUL_R_EILLACC;
		else
			return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_unset_default_app_by_operation(const char *app_id)
{
	int ret;

	if (app_id == NULL)
		return AUL_R_EINVAL;

	ret = aul_sock_send_raw(AUL_UTIL_PID, getuid(), APP_UNSET_APP_CONTROL_DEFAULT_APP,
			(unsigned char *)app_id, strlen(app_id), AUL_SOCK_NONE);
	if (ret != 0) {
		if (ret == -EILLEGALACCESS)
			return AUL_R_EILLACC;
		else
			return AUL_R_ERROR;
	}

	return AUL_R_OK;
}
