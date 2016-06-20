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

#pragma once

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <tzplatform_config.h>
#include <pkgmgr-info.h>

#include "aul_util.h"

#define REGULAR_UID_MIN 5000

typedef struct {
	char *appid;		/* appid */
	char *app_path;		/* exec */
	char *original_app_path;	/* exec */
	char *apptype;		/* app type */
	char *hwacc;		/* hwacceleration */
	char *pkg_id;
} app_info_from_db;

static inline char *_get_appid(app_info_from_db *menu_info)
{
	return menu_info ? menu_info->appid : NULL;
}

static inline char *_get_pkgid(app_info_from_db *menu_info)
{
	return menu_info ? menu_info->pkg_id : NULL;
}

static inline char *_get_app_path(app_info_from_db *menu_info)
{
	int i = 0;
	int path_len = -1;

	if (!menu_info || menu_info->app_path == NULL)
		return NULL;

	while (menu_info->app_path[i] != 0) {
		if (menu_info->app_path[i] == ' '
		    || menu_info->app_path[i] == '\t') {
			path_len = i;
			break;
		}
		i++;
	}

	if (path_len == 0) {
		free(menu_info->app_path);
		menu_info->app_path = NULL;
	} else if (path_len > 0) {
		char *tmp_app_path = malloc(sizeof(char) * (path_len + 1));
		if (tmp_app_path == NULL)
			return NULL;
		snprintf(tmp_app_path, path_len + 1, "%s", menu_info->app_path);
		free(menu_info->app_path);
		menu_info->app_path = tmp_app_path;
	}

	return menu_info->app_path;
}

static inline char *_get_original_app_path(app_info_from_db *menu_info)
{
	return menu_info ? menu_info->original_app_path : NULL;
}

static inline void _free_app_info_from_db(app_info_from_db *menu_info)
{
	if (menu_info != NULL) {
		if (menu_info->appid != NULL)
			free(menu_info->appid);
		if (menu_info->app_path != NULL)
			free(menu_info->app_path);
		if (menu_info->original_app_path != NULL)
			free(menu_info->original_app_path);
		if (menu_info->apptype != NULL)
			free(menu_info->apptype);
		if (menu_info->hwacc != NULL)
			free(menu_info->hwacc);
		if (menu_info->pkg_id != NULL)
			free(menu_info->pkg_id);
		free(menu_info);
	}
}

static inline app_info_from_db *_get_app_info_from_db_by_pkgname(
							const char *appid)
{
	app_info_from_db *menu_info = NULL;
	pkgmgrinfo_appinfo_h handle = NULL;
	int ret = PMINFO_R_OK;
	char *exec = NULL;
	char *apptype = NULL;

	menu_info = calloc(1, sizeof(app_info_from_db));
	if (menu_info == NULL)
		return NULL;

	if (appid == NULL) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}


	if (getuid() != GLOBAL_USER)
		ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, getuid(), &handle);
	else
		ret = pkgmgrinfo_appinfo_get_appinfo(appid, &handle);

	if (ret != PMINFO_R_OK) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	menu_info->appid = strdup(appid);

	ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	if (ret != PMINFO_R_OK)
		_E("fail to get exec from appinfo handle");

	if (exec)
		menu_info->app_path = strdup(exec);

	if (menu_info->app_path != NULL)
		menu_info->original_app_path = strdup(menu_info->app_path);

	ret = pkgmgrinfo_appinfo_get_apptype(handle, &apptype);
	if (ret != PMINFO_R_OK)
		_E("fail to get apptype from appinfo handle");

	if (apptype)
		menu_info->apptype = strdup(apptype);

	ret = pkgmgrinfo_appinfo_destroy_appinfo(handle);
	if (ret != PMINFO_R_OK)
		_E("pkgmgrinfo_appinfo_destroy_appinfo failed");

	if (!_get_app_path(menu_info)) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	return menu_info;
}

static inline int __appinfo_func(const pkgmgrinfo_appinfo_h appinfo,
		void *user_data)
{
	app_info_from_db *menu_info = (app_info_from_db *)user_data;
	char *apppath = NULL;
	char *pkgid = NULL;
	char *appid = NULL;
	char *apptype = NULL;
	int ret;

	if (!menu_info)
		return 0;

	ret = pkgmgrinfo_appinfo_get_exec(appinfo, &apppath);
	if (ret == PMINFO_R_OK && apppath) {
		menu_info->app_path = strdup(apppath);
		if (menu_info->app_path) {
			menu_info->original_app_path =
				strdup(menu_info->app_path);
		}
	}

	ret = pkgmgrinfo_appinfo_get_pkgid(appinfo, &pkgid);
	if (ret == PMINFO_R_OK && pkgid)
		menu_info->pkg_id = strdup(pkgid);

	ret = pkgmgrinfo_appinfo_get_appid(appinfo, &appid);
	if (ret == PMINFO_R_OK && appid)
		menu_info->appid = strdup(appid);

	ret = pkgmgrinfo_appinfo_get_apptype(appinfo, &apptype);
	if (ret == PMINFO_R_OK && apptype)
		menu_info->apptype = strdup(apptype);

	return ret;
}

static inline app_info_from_db *__get_app_info_from_db(const char *property,
		const char *value, uid_t uid)
{
	app_info_from_db *menu_info;
	pkgmgrinfo_appinfo_filter_h filter;
	int ret;

	if (uid < REGULAR_UID_MIN)
		uid = tzplatform_getuid(TZ_SYS_GLOBALAPP_USER);

	if (property == NULL || value == NULL)
		return NULL;

	menu_info = calloc(1, sizeof(app_info_from_db));
	if (menu_info == NULL) {
		_E("out of memory");
		return NULL;
	}

	ret = pkgmgrinfo_appinfo_filter_create(&filter);
	if (ret != PMINFO_R_OK) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	ret = pkgmgrinfo_appinfo_filter_add_string(filter, property, value);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	if (uid != GLOBAL_USER)
		ret = pkgmgrinfo_appinfo_usr_filter_foreach_appinfo(filter,
				__appinfo_func, (void *)menu_info, uid);
	else
		ret = pkgmgrinfo_appinfo_filter_foreach_appinfo(filter,
				__appinfo_func, (void *)menu_info);

	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_filter_destroy(filter);
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	pkgmgrinfo_appinfo_filter_destroy(filter);

	if (menu_info->appid == NULL || menu_info->app_path == NULL) {
		_free_app_info_from_db(menu_info);
		return NULL;
	}

	return menu_info;
}

static inline app_info_from_db *_get_app_info_from_db_by_appid_user(
		const char *appid, uid_t uid)
{
	return __get_app_info_from_db(PMINFO_APPINFO_PROP_APP_ID, appid, uid);
}

static inline app_info_from_db *_get_app_info_from_db_by_appid(
		const char *appid)
{
	return _get_app_info_from_db_by_appid_user(appid, getuid());
}

static inline app_info_from_db *_get_app_info_from_db_by_app_path_user(
		const char *app_path, uid_t uid)
{
	return __get_app_info_from_db(PMINFO_APPINFO_PROP_APP_EXEC, app_path,
			uid);
}

static inline app_info_from_db *_get_app_info_from_db_by_app_path(
		const char *app_path)
{
	return _get_app_info_from_db_by_app_path_user(app_path, getuid());
}

