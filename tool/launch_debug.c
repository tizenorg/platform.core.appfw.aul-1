/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include <bundle.h>
#include <bundle_internal.h>
#include <pkgmgr-info.h>

#include "aul.h"
#include "launch.h"

#define DEBUG_LAUNCHPAD_SOCK ".debug-launchpad-sock"
#define DLP_K_ATTACH_ARG "__DLP_ATTACH_ARG__"
#define DLP_K_GDBSERVER_PATH "__DLP_GDBSERVER_PATH__"
#define SDK_ATTACH "ATTACH"

static bundle *create_internal_bundle(int argc, char **argv)
{
	bundle *b;
	int i;
	int j;
	int cnt;
	char *arg[1024] = {0, };

	b = bundle_create();
	if (b == NULL)
		return NULL;

	for (i = 2; i < argc - 1; i++) {
		if ((i + 1) > (argc - 1)) {
			bundle_add(b, argv[1], " ");
		} else if (argv[i] && strcmp(argv[i], AUL_K_SDK) == 0) {
			bundle_add(b, AUL_K_SDK, argv[i + 1]);
		} else if (argv[i] && strcmp(argv[i], DLP_K_ATTACH_ARG) == 0) {
			arg[0] = strtok(argv[i + 1], ",");

			cnt = 1;
			while ((arg[cnt] = strtok(NULL, ",")) != NULL)
				cnt++;

			bundle_add(b, SDK_ATTACH, DLP_K_ATTACH_ARG);
			bundle_add_str_array(b, DLP_K_ATTACH_ARG, NULL, cnt);

			for (j = 0; j < cnt; j++)
				bundle_set_str_array_element(b, DLP_K_ATTACH_ARG, j, arg[j]);
		} else if (argv[i] && strcmp(argv[i], DLP_K_GDBSERVER_PATH) == 0) {
			bundle_add(b, DLP_K_GDBSERVER_PATH, argv[i + 1]);
		}
	}

	return b;
}

static void print_usage(char *progname)
{
	printf("[usage] %s [appid] %s %s %s <gdbserver_path> %s --attach,:[port],[pid]\n",
			progname, AUL_K_SDK, SDK_ATTACH, DLP_K_GDBSERVER_PATH, DLP_K_ATTACH_ARG);
	printf("ex) $ %s [appid] %s %s %s /usr/bin/gdbserver %s --attach,:10003,1234\n",
			progname, AUL_K_SDK, SDK_ATTACH, DLP_K_GDBSERVER_PATH, DLP_K_ATTACH_ARG);
}

static int __get_gles(void)
{
	FILE *fp;
	char buf[PATH_MAX];
	char *tmp;
	int gles = 1;

	fp = fopen("/proc/cmdline", "r");
	if (fp == NULL)
		return gles;

	if (fgets(buf, sizeof(buf), fp) != NULL) {
		tmp = strstr(buf, "gles");
		if (tmp != NULL)
			sscanf(tmp, "gles=%d", &gles);
	}

	fclose(fp);

	return gles;
}

static void __set_pkg_api_version(bundle *kb, const char *pkgid)
{
	int ret;
	char *api_version;
	pkgmgrinfo_pkginfo_h handle;

	ret = pkgmgrinfo_pkginfo_get_pkginfo(pkgid, &handle);
	if (ret != PMINFO_R_OK)
		return;

	ret = pkgmgrinfo_pkginfo_get_api_version(handle, &api_version);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return;
	}

	printf("pkg api_version: %s\n", api_version);
	bundle_add(kb, AUL_K_API_VERSION, api_version);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
}

static int __set_appinfo_for_debug_launchpad(bundle *kb, const char *appid)
{
	pkgmgrinfo_appinfo_h handle;
	int ret;
	char *pkgid;
	char *exec;
	char *apptype;
	char *pkgtype;
	char *component_type;
	pkgmgrinfo_app_hwacceleration hwacc = PMINFO_HWACCELERATION_OFF;
	const char *hwacc_str = "NOT_USE";
	bool process_pool = false;

	if (kb == NULL)
		return -1;

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, getuid(), &handle);
	if (ret != PMINFO_R_OK)
		return -1;

	ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	if (ret != PMINFO_R_OK)
		goto end;

	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	if (ret != PMINFO_R_OK)
		goto end;

	ret = pkgmgrinfo_appinfo_get_apptype(handle, &apptype);
	if (ret != PMINFO_R_OK)
		goto end;

	ret = pkgmgrinfo_appinfo_get_pkgtype(handle, &pkgtype);
	if (ret != PMINFO_R_OK)
		goto end;

	ret = pkgmgrinfo_appinfo_get_component_type(handle, &component_type);
	if (ret != PMINFO_R_OK)
		goto end;

	ret = pkgmgrinfo_appinfo_get_hwacceleration(handle, &hwacc);
	if (ret != PMINFO_R_OK)
		goto end;

	ret = pkgmgrinfo_appinfo_is_process_pool(handle, &process_pool);
	if (ret != PMINFO_R_OK)
		goto end;

	if (__get_gles()) {
		if (hwacc == PMINFO_HWACCELERATION_OFF)
			hwacc_str = "NOT_USE";
		else if (hwacc == PMINFO_HWACCELERATION_ON)
			hwacc_str = "USE";
		else
			hwacc_str = "SYS";
	}

	bundle_add(kb, AUL_K_APPID, appid);
	bundle_add(kb, AUL_K_HWACC, hwacc_str);
	bundle_add(kb, AUL_K_EXEC, exec);
	bundle_add(kb, AUL_K_APP_TYPE, apptype);
	bundle_add(kb, AUL_K_PKGID, pkgid);
	bundle_add(kb, AUL_K_INTERNAL_POOL, process_pool ? "true" : "false");
	bundle_add(kb, AUL_K_COMP_TYPE, component_type);
	bundle_add(kb, AUL_K_PACKAGETYPE, pkgtype);

	__set_pkg_api_version(kb, pkgid);

end:
	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	bundle *b;

	if (argc < 2) {
		print_usage(argv[0]);
		return -1;
	}

	b = create_internal_bundle(argc, argv);
	if (b == NULL) {
		printf("out of memory\n");
		return -1;
	}

	if (bundle_get_type(b, AUL_K_SDK) == BUNDLE_TYPE_NONE) {
		print_usage(argv[0]);
		bundle_free(b);
		return -1;
	}

	__set_appinfo_for_debug_launchpad(b, argv[1]);

	ret = app_send_cmd_to_launchpad(DEBUG_LAUNCHPAD_SOCK,
			getuid(), 0, b);
	if (ret < 0)
		printf("Failed to launch %s\n", argv[1]);

	bundle_free(b);

	return 0;
}
