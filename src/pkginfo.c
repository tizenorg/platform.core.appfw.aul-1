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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aul.h"
#include "aul_api.h"
#include "menu_db_util.h"
#include "simple_util.h"

typedef struct _internal_param_t {
	aul_app_info_iter_fn enum_fn;
	void *user_param;
} internal_param_t;

static int __get_pkginfo(const char *dname, const char *cmdline, void *priv);
static int __get_pkgname_bypid(int pid, char *pkgname, int len);


SLPAPI int aul_app_is_running(const char *pkgname)
{
	char *apppath = NULL;
	ail_appinfo_h handle;
	ail_error_e ail_ret;

	int ret = 0;
	int i = 0;

	if (pkgname == NULL)
		return 0;

	ail_ret = ail_package_get_appinfo(pkgname, &handle);
	if (ail_ret != AIL_ERROR_OK) {
		_E("ail_package_get_appinfo with %s failed", pkgname);
		return ret;
	}

	ail_ret = ail_appinfo_get_str(handle, AIL_PROP_EXEC_STR, &apppath);
	if (ail_ret != AIL_ERROR_OK) {
		_E("ail_appinfo_get_str failed");
		goto out;
	}
	
	if (apppath == NULL)
		goto out;

	/*truncate apppath if it includes default bundles */
	while (apppath[i] != 0) {
		if (apppath[i] == ' ' || apppath[i] == '\t') {
			apppath[i]='\0';
			break;
		}
		i++;
	}
	
	if (__proc_iter_cmdline(NULL, apppath) > 0)
		ret = 1;
	else
		ret = 0;

 out:
	if (ail_package_destroy_appinfo(handle) != AIL_ERROR_OK)
		_E("ail_destroy_rs failed");
	return ret;
}

static int __get_pkginfo(const char *dname, const char *cmdline, void *priv)
{
	internal_param_t *p;
	app_info_from_db *menu_info;
	aul_app_info info;

	p = (internal_param_t *) priv;
	if ((menu_info = _get_app_info_from_db_by_apppath(cmdline)) == NULL)
		goto out;
	else {
		info.pid = atoi(dname);
		info.pkg_name = _get_pkgname(menu_info);
		info.app_path = _get_app_path(menu_info);
		_D("get pkginfo - %d %s", info.pid, info.app_path);
		p->enum_fn(&info, p->user_param);
	}

 out:
	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);
	return 0;
}

SLPAPI int aul_app_get_running_app_info(aul_app_info_iter_fn enum_fn,
					void *user_param)
{
	internal_param_t param;

	if (enum_fn == NULL)
		return AUL_R_EINVAL;

	param.enum_fn = enum_fn;
	param.user_param = user_param;

	__proc_iter_cmdline(__get_pkginfo, &param);

	return AUL_R_OK;
}

static int __get_pkgname_bypid(int pid, char *pkgname, int len)
{
	char *cmdline;
	app_info_from_db *menu_info;

	cmdline = __proc_get_cmdline_bypid(pid);
	if (cmdline == NULL)
		return -1;

	if ((menu_info = _get_app_info_from_db_by_apppath(cmdline)) == NULL) {
		free(cmdline);
		return -1;
	} else
		snprintf(pkgname, len, "%s", _get_pkgname(menu_info));

	free(cmdline);
	_free_app_info_from_db(menu_info);

	return 0;
}

SLPAPI int aul_app_get_pkgname_bypid(int pid, char *pkgname, int len)
{
	int pgid;

	if (pkgname == NULL)
		return AUL_R_EINVAL;

	if (__get_pkgname_bypid(pid, pkgname, len) == 0) {
		_D("Pkg name for %d is %s", pid, pkgname);
		return AUL_R_OK;
	}
	/* support app launched by shell script*/
	_D("second chance");
	pgid = getpgid(pid);
	if (pgid <= 1)
		return AUL_R_ERROR;

	_D("second change pgid = %d, pid = %d", pgid, pid);
	if (__get_pkgname_bypid(pgid, pkgname, len) == 0)
		return AUL_R_OK;

	return AUL_R_ERROR;
}

