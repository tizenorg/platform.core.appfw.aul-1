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

#define _MAX_PACKAGE_ID_LEN 256

#define _GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define _EXTERNAL_APP_SPECIFIC_PATH tzplatform_mkpath(TZ_SYS_STORAGE, "sdcard/apps/")
#define _APP_SPECIFIC_PATH tzplatform_getenv(TZ_USER_APP)

static const char _DATA_DIR[] = "data/";
static const char _CACHE_DIR[] = "cache/";
static const char _RESOURCE_DIR[] = "res/";
static const char _SHARED_DATA_DIR[] = "shared/data/";
static const char _SHARED_TRUSTED_DIR[] = "shared/trusted/";
static const char _SHARED_RESOURCE_DIR[] = "shared/res/";

static int __get_pkgid_by_appid(char *pkgid, int pkgid_len, const char *appid, uid_t uid)
{
	pkgmgrinfo_appinfo_h handle;
	char *tmp_pkgid = NULL;
	int ret;

	ret = pkgmgrinfo_appinfo_get_appinfo(appid, &handle);
	if (ret != PMINFO_R_OK) {
		ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, uid, &handle);
		if (ret != PMINFO_R_OK) {
			_E("Failed to get app info. (ret:%d)", ret);
			return AUL_R_ENOAPP;
		}
	}

	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &tmp_pkgid);
	if (ret != PMINFO_R_OK) {
		_E("Failed to get pkgid. (ret:%d)", ret);
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return AUL_R_ENOAPP;
	}

	strncat(pkgid, tmp_pkgid, pkgid_len);
	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return AUL_R_OK;
}

static int __get_path(char **path, const char *appid, const char *dir_name, bool external, uid_t uid)
{
	char *tmp_path;
	char pkgid[_MAX_PACKAGE_ID_LEN] = {0,};
	int ret = AUL_R_OK;
	pkgmgrinfo_pkginfo_h handle;

	if (appid == NULL) {
		appid = (char *)calloc(_MAX_PACKAGE_ID_LEN, sizeof(char));
		int ret = aul_app_get_appid_bypid(getpid(), appid, _MAX_PACKAGE_ID_LEN - 1);
		if (ret != AUL_R_OK)
			return ret;
	}

	ret = __get_pkgid_by_appid(pkgid, _MAX_PACKAGE_ID_LEN - 1, appid, uid);
	if (ret != AUL_R_OK)
		return ret;

	*path = (char *)calloc(PATH_MAX, sizeof(char));
	if (*path == NULL)
		return AUL_R_ERROR;

	if (external) {
		if (dir_name == NULL)
			snprintf(*path, PATH_MAX, "%s%s", _EXTERNAL_APP_SPECIFIC_PATH, pkgid);
		else
			snprintf(*path, PATH_MAX, "%s%s/%s", _EXTERNAL_APP_SPECIFIC_PATH, pkgid, dir_name);
	} else {
		ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
		if (ret != PMINFO_R_OK) {
			ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle);
			if (ret != PMINFO_R_OK) {
				_E("Failed to get pkgid. (ret:%d)", ret);
				pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
				return AUL_R_ENOAPP;
			}
		}
		ret = pkgmgrinfo_pkginfo_get_root_path(handle, &tmp_path);
		if (ret != PMINFO_R_OK) {
			_E("Failed to get pkgid. (ret:%d)", ret);
			pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
			return AUL_R_ERROR;
		}
		if (dir_name == NULL)
			snprintf(*path, PATH_MAX, "%s", tmp_path);
		else
			snprintf(*path, PATH_MAX, "%s/%s", tmp_path, dir_name);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}

	return AUL_R_OK;
}

SLPAPI const char *aul_get_app_external_root_path(void)
{
	char *path;
	__get_path(&path, NULL, NULL, false, getuid());
	return path;
}

SLPAPI const char *aul_get_app_root_path(void)
{
	char *path;
	__get_path(&path, NULL, NULL, false, getuid());
	return path;
}

SLPAPI const char *aul_get_app_data_path(void)
{
	char *path;
	__get_path(&path, NULL, _DATA_DIR, false, getuid());
	return path;
}

SLPAPI const char *aul_get_app_cache_path(void)
{
	char *path;
	__get_path(&path, NULL, _CACHE_DIR, false, getuid());
	return path;
}

SLPAPI const char *aul_get_app_resource_path(void)
{
	char *path;
	__get_path(&path, NULL, _RESOURCE_DIR, false, getuid());
	return path;
}

SLPAPI const char *aul_get_app_shared_data_path(void)
{
	char *path;
	__get_path(&path, NULL, _SHARED_DATA_DIR, false, getuid());
	return path;
}

SLPAPI const char *aul_get_app_shared_resource_path(void)
{
	char *path;
	__get_path(&path, NULL, _SHARED_RESOURCE_DIR, false, getuid());
	return path;
}

SLPAPI const char *aul_get_app_shared_trusted_path(void)
{
	char *path;
	__get_path(&path, NULL, _SHARED_TRUSTED_DIR, false, getuid());
	return path;
}

SLPAPI const char *aul_get_app_external_data_path(void)
{
	char *path;
	__get_path(&path, NULL, _DATA_DIR, true, getuid());
	return path;
}

SLPAPI const char *aul_get_app_external_cache_path(void)
{
	char *path;
	__get_path(&path, NULL, _CACHE_DIR, true, getuid());
	return path;
}

SLPAPI const char *aul_get_app_external_shared_data_path(void)
{
	char *path;
	__get_path(&path, NULL, _SHARED_DATA_DIR, true, getuid());
	return path;
}

SLPAPI const char *aul_get_app_specific_path(void)
{
	return _APP_SPECIFIC_PATH;
}

SLPAPI const char *aul_get_app_external_specific_path(void)
{
	return _EXTERNAL_APP_SPECIFIC_PATH;
}

SLPAPI int aul_get_app_shared_data_path_by_appid(const char *appid, char **path)
{
	return __get_path(path, appid, _SHARED_DATA_DIR, false, _GLOBAL_USER);
}

SLPAPI int aul_get_app_shared_resource_path_by_appid(const char *appid, char **path)
{
	return __get_path(path, appid, _SHARED_RESOURCE_DIR, false, _GLOBAL_USER);
}

SLPAPI int aul_get_app_shared_trusted_path_by_appid(const char *appid, char **path)
{
	return __get_path(path, appid, _SHARED_TRUSTED_DIR, false, _GLOBAL_USER);
}

SLPAPI int aul_get_app_external_shared_data_path_by_appid(const char *appid, char **path)
{
	return __get_path(path, appid, _SHARED_DATA_DIR, true, _GLOBAL_USER);
}

SLPAPI int aul_get_usr_app_shared_data_path_by_appid(const char *appid, char **path, uid_t uid)
{
	return __get_path(path, appid, _SHARED_DATA_DIR, false, uid);
}

SLPAPI int aul_get_usr_app_shared_resource_path_by_appid(const char *appid, char **path, uid_t uid)
{
	return __get_path(path, appid, _SHARED_RESOURCE_DIR, false, uid);
}

SLPAPI int aul_get_usr_app_shared_trusted_path_by_appid(const char *appid, char **path, uid_t uid)
{
	return __get_path(path, appid, _SHARED_TRUSTED_DIR, false, uid);
}

SLPAPI int aul_get_usr_app_external_shared_data_path_by_appid(const char *appid, char **path, uid_t uid)
{
	return __get_path(path, appid, _SHARED_DATA_DIR, true, uid);
}
