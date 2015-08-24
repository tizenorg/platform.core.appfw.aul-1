/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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

#include <unistd.h>
#include <linux/limits.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <tzplatform_config.h>
#include <pkgmgr-info.h>

#include "aul_api.h"
#include "aul_util.h"
#include "simple_util.h"
#include "aul.h"

#define ROOT_UID 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define _EXTERNAL_APP_SPECIFIC_PATH \
	tzplatform_mkpath(TZ_SYS_STORAGE, "sdcard/apps/")
#define _APP_SPECIFIC_PATH tzplatform_getenv(TZ_USER_APP)

static const char _DATA_DIR[] = "data/";
static const char _CACHE_DIR[] = "cache/";
static const char _RESOURCE_DIR[] = "res/";
static const char _TEP_RESOURCE_DIR[] = "res/tep/";
static const char _SHARED_DATA_DIR[] = "shared/data/";
static const char _SHARED_TRUSTED_DIR[] = "shared/trusted/";
static const char _SHARED_RESOURCE_DIR[] = "shared/res/";

static const char * __get_specific_path(uid_t uid)
{
	const char * path;
	if (uid == ROOT_UID || uid == GLOBAL_USER)
		path = tzplatform_getenv(TZ_SYS_RO_APP);
	else {
		tzplatform_set_user(uid);
		path = tzplatform_getenv(TZ_USER_APP);
		tzplatform_reset_user();
	}
	return path;
}

static int __get_pkgid(char *pkgid, int len, const char *appid, uid_t uid)
{
	pkgmgrinfo_appinfo_h appinfo;
	char *_pkgid;
	int ret;
	char buf[NAME_MAX];
	const char *_appid;

	if (appid == NULL) {
		ret = aul_app_get_appid_bypid(getpid(), buf, sizeof(buf));
		if (ret != AUL_R_OK)
			return ret;

		_appid = buf;
	} else {
		_appid = appid;
	}

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(_appid, uid, &appinfo);
	if (ret != PMINFO_R_OK) {
		if (ret != PMINFO_R_OK) {
			_E("Failed to get app info. (ret:%d)", ret);
			return AUL_R_ENOAPP;
		}
	}

	ret = pkgmgrinfo_appinfo_get_pkgid(appinfo, &_pkgid);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get pkgid. (ret:%d)", ret);
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
		return AUL_R_ENOAPP;
	}

	snprintf(pkgid, len, "%s", _pkgid);
	pkgmgrinfo_appinfo_destroy_appinfo(appinfo);

	return AUL_R_OK;
}

static const char *__get_path(char **path, const char *appid,
		const char *dir_name, uid_t uid,
		bool ext)
{
	char buf[PATH_MAX];
	char pkgid[NAME_MAX];
	int ret;

	if (*path)
		return *path;

	ret = __get_pkgid(pkgid, sizeof(pkgid), appid, uid);
	if (ret != AUL_R_OK)
		return ret;

	if (ext) {
		snprintf(buf, sizeof(buf), "%s%s/%s", _EXTERNAL_APP_SPECIFIC_PATH,
				pkgid, dir_name ? dir_name : "");
	} else {
		snprintf(buf, sizeof(buf), "%s/%s/%s", __get_specific_path(uid),
				pkgid, dir_name ? dir_name : "");
	}

	assert(path);
	*path = strdup(buf);

	return *path;
}

SLPAPI const char *aul_get_app_external_root_path(void)
{
	static char *path;

	return __get_path(&path, NULL, NULL, getuid(), true);
}

SLPAPI const char *aul_get_app_root_path(void)
{
	static char *path;

	return __get_path(&path, NULL, NULL, getuid(), false);
}

SLPAPI const char *aul_get_app_data_path(void)
{
	static char *path;

	return __get_path(&path, NULL, _DATA_DIR, getuid(), false);
}

SLPAPI const char *aul_get_app_cache_path(void)
{
	static char *path;

	return __get_path(&path, NULL, _CACHE_DIR, getuid(), false);
}

SLPAPI const char *aul_get_app_resource_path(void)
{
	static char *path;

	return __get_path(&path, NULL, _RESOURCE_DIR, getuid(), false);
}

SLPAPI const char *aul_get_app_tep_resource_path(void)
{
	static char *path;

	return __get_path(&path, NULL, _TEP_RESOURCE_DIR, getuid(), false);
}

SLPAPI const char *aul_get_app_shared_data_path(void)
{
	static char *path;

	return __get_path(&path, NULL, _SHARED_DATA_DIR, getuid(), false);
}

SLPAPI const char *aul_get_app_shared_resource_path(void)
{
	static char *path;

	return __get_path(&path, NULL, _SHARED_RESOURCE_DIR, getuid(), false);
}

SLPAPI const char *aul_get_app_shared_trusted_path(void)
{
	static char *path;

	return __get_path(&path, NULL, _SHARED_TRUSTED_DIR, getuid(), false);
}

SLPAPI const char *aul_get_app_external_data_path(void)
{
	static char *path;

	return __get_path(&path, NULL, _DATA_DIR, getuid(), true);
}

SLPAPI const char *aul_get_app_external_cache_path(void)
{
	static char *path;

	return __get_path(&path, NULL, _CACHE_DIR, getuid(), true);
}

SLPAPI const char *aul_get_app_external_shared_data_path(void)
{
	static char *path;

	return __get_path(&path, NULL, _SHARED_DATA_DIR, getuid(),
			true);
}

SLPAPI const char *aul_get_app_specific_path(void)
{
	return __get_specific_path(getuid());
}

SLPAPI const char *aul_get_app_external_specific_path(void)
{
	return _EXTERNAL_APP_SPECIFIC_PATH;
}

SLPAPI int aul_get_app_shared_data_path_by_appid(const char *appid, char **path)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path(path, appid, _SHARED_DATA_DIR, getuid(), false);
}

SLPAPI int aul_get_app_shared_resource_path_by_appid(const char *appid,
		char **path)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path(path, appid, _SHARED_RESOURCE_DIR, getuid(), false);
}

SLPAPI int aul_get_app_shared_trusted_path_by_appid(const char *appid,
		char **path)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path(path, appid, _SHARED_TRUSTED_DIR, getuid(), false);
}

SLPAPI int aul_get_app_external_shared_data_path_by_appid(const char *appid,
		char **path)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path(path, appid, _SHARED_DATA_DIR, getuid(), true);
}

SLPAPI int aul_get_usr_app_shared_data_path_by_appid(const char *appid,
		char **path, uid_t uid)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path(path, appid, _SHARED_DATA_DIR, uid, false);
}

SLPAPI int aul_get_usr_app_shared_resource_path_by_appid(const char *appid,
		char **path, uid_t uid)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path(path, appid, _SHARED_RESOURCE_DIR, uid, false);
}

SLPAPI int aul_get_usr_app_shared_trusted_path_by_appid(const char *appid,
		char **path, uid_t uid)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path(path, appid, _SHARED_TRUSTED_DIR, uid, false);
}

SLPAPI int aul_get_usr_app_external_shared_data_path_by_appid(const char *appid,
		char **path, uid_t uid)
{
	if (appid == NULL || path == NULL)
		return AUL_R_EINVAL;

	return __get_path(path, appid, _SHARED_DATA_DIR, uid, true);
}
