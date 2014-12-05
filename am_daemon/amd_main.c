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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <aul.h>
#include <vconf.h>
#include <app-checker-server.h>
#include <ail.h>
#include <glib.h>
#include <stdlib.h>
#include <tzplatform_config.h>

#include "amd_config.h"
#include "simple_util.h"
#include "aul_util.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "amd_launch.h"
#include "amd_request.h"


#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

typedef struct _r_app_info_t{
	char pkg_name[MAX_PACKAGE_STR_SIZE];
	int pid;
	uid_t user;
} r_app_info_t;

GSList *r_app_info_list = NULL;

static void __vconf_cb(keynode_t *key, void *data);
static int __init();

extern int _status_init(struct amdmgr* amd);

static int __send_to_sigkill(int pid)
{
	int pgid;

	pgid = getpgid(pid);
	if (pgid <= 1)
		return -1;

	if (killpg(pgid, SIGKILL) < 0)
		return -1;

	return 0;
}

static int __kill_bg_apps(int limit)
{
	int len;
	int i;
	int n;
	r_app_info_t *info_t = NULL;
	GSList *iter = NULL;

	len = g_slist_length(r_app_info_list);

	n = len - limit;

	if (n<=0) return 0;

	for ( i=0, iter = r_app_info_list; i<n ; i++) {
		info_t = (r_app_info_t *)iter->data;
		__send_to_sigkill(info_t->pid);
		iter = g_slist_next(iter);
		r_app_info_list = g_slist_remove(r_app_info_list, info_t);
		free(info_t);
	}

	return 0;
}

static int __remove_item_running_list(int pid, uid_t user)
{
	r_app_info_t *info_t = NULL;
	GSList *iter = NULL;

	for (iter = r_app_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (r_app_info_t *)iter->data;
		if( (pid == info_t->pid) && (user == info_t->user || 0 == info_t->user )) {
			r_app_info_list = g_slist_remove(r_app_info_list, info_t);
			free(info_t);
			break;
		}
	}
	return 0;
}

gboolean __add_item_running_list(gpointer user_data)
{
	bool taskmanage;
	ail_appinfo_h handle = NULL;
	ail_error_e ail_ret;
	r_app_info_t *info_t = NULL;
	GSList *iter = NULL;
	int found = 0;
	int limit;
	char *pkgname;
	int pid;
	uid_t user;
	item_pkt_t *item;

	item = (item_pkt_t *)user_data;

	pkgname = item->appid;
	pid = item->pid;
    user = item->uid;
	if (vconf_get_int(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS, &limit) != 0){
		_E("Unable to get VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS\n");
	}

	if (pkgname == NULL) {
		return false;
	} else if (strncmp(pkgname, "org.tizen.cluster-home", 24) == 0) {
		if(limit>0) __kill_bg_apps(limit-1);
		return false;
	}
	//is admin is global
	if (user != GLOBAL_USER)
		ail_ret = ail_package_get_usr_appinfo(pkgname, user, &handle);
	else
		ail_ret = ail_package_get_appinfo(pkgname, &handle);
	if (ail_ret != AIL_ERROR_OK) {
		_E("ail_get_appinfo with %s failed", pkgname);
		return false;
	}

	ail_ret = ail_appinfo_get_bool(handle, AIL_PROP_X_SLP_TASKMANAGE_BOOL, &taskmanage);
	if (ail_ret != AIL_ERROR_OK) {
		_E("ail_appinfo_get_bool failed");
		goto END;
	}

	if (taskmanage == false)
		goto END;

	for (iter = r_app_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (r_app_info_t *)iter->data;
		if((pid == info_t->pid) && (user == info_t->user))  {
			found = 1;
			r_app_info_list = g_slist_remove(r_app_info_list, info_t);
			r_app_info_list = g_slist_append(r_app_info_list, info_t);
			break;
		}
	}
	if(found == 0) {
		info_t = malloc(sizeof(r_app_info_t));
		strncpy(info_t->pkg_name, pkgname, MAX_PACKAGE_STR_SIZE-1);
		info_t->pid = pid;
		r_app_info_list = g_slist_append(r_app_info_list, info_t);
	}

	for (iter = r_app_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (r_app_info_t *)iter->data;
	}

	if(limit>0) __kill_bg_apps(limit);

	for (iter = r_app_info_list; iter != NULL; iter = g_slist_next(iter))
	{
		info_t = (r_app_info_t *)iter->data;
	}

END:
	if (ail_destroy_appinfo(handle) != AIL_ERROR_OK)
		_E("ail_destroy_rs failed");

	free(item);
	return false;
}

static void __vconf_cb(keynode_t *key, void *data)
{
	int limit;
	const char *name;

	name = vconf_keynode_get_name(key);
	if( name == NULL ) {
		return;
	}else if ( strcmp(name, VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS) == 0){
		limit = vconf_keynode_get_int(key);
		if(limit>0) __kill_bg_apps(limit);
	}
}

int __app_dead_handler(int pid, uid_t user)
{
	// this function was called in single user mode as a callback to aul_listen_app_dead_signal
	// but in multiuser mode, AMD daemon can't listen any more on DBUS system to catch those events
	// AMD Agents must connect to AMD Daemon to signal a dead process
	__remove_item_running_list(pid, user);
	_status_remove_app_info_list(pid, user);
	return 0;
}

static void __start_cb(void *user_data,
		const char *filename, const struct appinfo *ai)
{
	/*struct amdmgr *amd = user_data;*/
	const char *componet = NULL;
	int r;

	componet = appinfo_get_value(ai, AIT_COMP);

	r = appinfo_get_boolean(ai, AIT_ONBOOT);
	if (r == 1 && strncmp(componet, "svc", 3) == 0)
		_start_srv(ai, NULL);
}

static void _start_services(struct amdmgr *amd)
{
	appinfo_foreach(amd->af, __start_cb, amd);
}

static int __init()
{
	struct amdmgr amd = {
		.af = NULL,
	};

	int ret=0;

	appinfo_init(&amd.af);
	_requset_init(&amd);
	_launch_init(&amd);
	_status_init(&amd);

	if (vconf_notify_key_changed(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS, __vconf_cb, NULL) != 0)
		_E("Unable to register callback for VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS\n");

	_start_services(&amd);

	return 0;
}

gboolean  __amd_ready(gpointer user_data)
{
	int fd;

	fd = creat("/run/amd_ready", S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

	if (fd == -1) {
		_E("failed to create /run/amd_ready: %s\n",
			strerror(errno));
		return FALSE;
	}

	close(fd);
	return FALSE;
}

int main(int argc, char *argv[])
{
	GMainLoop *mainloop = NULL;

	if (ac_server_initialize() != AC_R_OK){
		_E("ac_server_initialize failed!\n");
		return -1;
	}
	if (__init() != 0){
		_E("AMD Initialization failed!\n");
		return -1;
	}

	g_idle_add(__amd_ready, NULL);

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		_E("failed to create glib main loop");
		return -1;
	}
	g_main_loop_run(mainloop);

	return 0;
}
