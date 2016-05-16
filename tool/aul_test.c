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

#include <poll.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib.h>

#include <bundle_internal.h>

#include "menu_db_util.h"
#include "aul.h"
#define PERF_ACTIVATE
#include "perf.h"

#define MAX_LOCAL_BUFSZ 128
#define QUERY_LEN	10240

static char **gargv;
static int gargc;
static char *cmd;
static int apn_pid;
static GMainLoop *mainloop = NULL;

typedef struct _test_func_t {
	char *name;
	int (*func) ();
	char *desc;
	char *usage;
} test_func_t;

static bundle *create_internal_bundle(int start)
{
	bundle *kb;
	int i;

	kb = bundle_create();
	for (i = start; i < gargc - 1; i++) {
		if ((i + 1) > gargc - 1)
			bundle_add(kb, gargv[i], " ");
		else
			bundle_add(kb, gargv[i], gargv[i + 1]);
	}

	return kb;
}

int launch_test()
{
	static int num = 0;
	int ret = 0;
	bundle *kb = NULL;

	kb = create_internal_bundle(3);
	if (kb == NULL)
		return -1;

	printf("[aul_launch_app %d test] %s \n", num++, gargv[2]);

	ret = aul_launch_app(gargv[2], kb);

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}
	return ret;
}

int launch_test_for_uid()
{
	static int num = 0;
	int ret = 0;
	bundle *kb = NULL;

	kb = create_internal_bundle(3);
	if (kb == NULL)
		return -1;

	printf("[aul_launch_app %d test] %s \n", num++, gargv[2]);

	ret = aul_launch_app_for_uid(gargv[2], kb, atoi(gargv[3]));

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}
	return ret;
}

int dbus_launch_test()
{
	bundle *kb = NULL;
	int ret = 0;

	kb = create_internal_bundle(3);

	if (kb == NULL)
		return -1;

	ret = aul_launch_app(gargv[2], kb);

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}

	return ret;
}

int open_test()
{
	static int num = 0;

	printf("[aul_open_app %d test] %s \n", num++, gargv[2]);
	return aul_open_app(gargv[2]);
}

int resume_test()
{
	static int num = 0;

	printf("[aul_open_app %d test] %s \n", num++, gargv[2]);
	return aul_resume_app(gargv[2]);
}

int resume_pid_test()
{
	static int num = 0;
	printf("[aul_resume_pid %d test] %d \n", num++, apn_pid);
	return aul_resume_pid(apn_pid);
}

int term_pid_test()
{
	static int num = 0;
	printf("[aul_term_pid %d test] %d \n", num++, apn_pid);
	return aul_terminate_pid(apn_pid);
}

int term_req_pid_test()
{
	static int num = 0;
	printf("[aul_subapp_terminate_request_pid %d test] %d \n", num++, apn_pid);
	return aul_subapp_terminate_request_pid(apn_pid);
}

int term_pid_without_restart_test(void)
{
	static int num = 0;
	printf("[aul_term_pid_without_restart %d test] %d \n", num++, apn_pid);
	return aul_terminate_pid_without_restart(apn_pid);
}

int term_bgapp_pid_test(void)
{
	static int num = 0;
	printf("[aul_term_pid_without_restart %d test] %d \n", num++, apn_pid);
	return aul_terminate_bgapp_pid(apn_pid);
}

int pause_test(void)
{
	static int num = 0;

	printf("[aul_pause_app %d test] %s \n", num++, gargv[2]);
	return aul_pause_app(gargv[2]);
}

int pause_pid_test(void)
{
	static int num = 0;

	printf("[aul_pause_pid %d test] %d \n", num++, apn_pid);
	return aul_pause_pid(apn_pid);
}

static test_func_t scn_func[] = {
	{"n", launch_test, "launch_test", ""},
	{"n", launch_test, "launch_test", ""},
	{"n", resume_test, "open_test", ""},
	{"n", resume_test, "open_test", ""},
	{"p", resume_pid_test, "resume_pid_test", ""},
	{"p", resume_pid_test, "resume_pid_test", ""},
	{"p", term_pid_test, "term_pid_test", ""},
	{"n", resume_test, "open_test", ""},
	{"n", launch_test, "launch_test", ""}
};

int all_test()
{
	static int pos = 0;
	int ret;

	if (pos > sizeof(scn_func) / sizeof(test_func_t) - 1) {
		printf("all internal test done\n");
		return 0;
	}

	if (strncmp(scn_func[pos].name, "n", 1) == 0) {
		printf("[test %d] %s , pkgname = %s\n", pos, scn_func[pos].desc,
		       gargv[2]);
		apn_pid = scn_func[pos].func();
		printf("... return pid = %d\n", apn_pid);
	} else {
		printf("[test %d] %s , pid = %d\n", pos, scn_func[pos].desc,
		       apn_pid);
		ret = scn_func[pos].func();
		printf("... return res = %d\n", ret);
	}
	pos++;

	return 0;
}

int is_run_test()
{
	if (aul_app_is_running(gargv[2]))
		printf("... %s is running\n", gargv[2]);
	else
		printf("... %s is not running\n", gargv[2]);

	return 0;
}

int iterfunc(const aul_app_info *info, void *data)
{
	printf("\t==========================\n");
	printf("\t appid: %s\n", info->appid);
	printf("\t app_path: %s\n", info->app_path);
	printf("\t running pid: %d\n", info->pid);
	printf("\t==========================\n");

	return 0;
}

int get_allpkg_test()
{
	static int num = 0;
	printf("[aul_app_get_ruuning_app_info %d test] \n", num++);
	return aul_app_get_running_app_info(iterfunc, NULL);
}

int iterfunc_status(const aul_app_info *info, void *data)
{
	printf("\t==========================\n");
	printf("\t pid: %d\n", info->pid);
	printf("\t appid: %s\n", info->appid);
	printf("\t app_path: %s\n", info->app_path);
	printf("\t pkgid: %s\n", info->pkgid);
	printf("\t status: %d\n", info->status);
	printf("\t is_sub_app : %d\n", info->is_sub_app);
	printf("\t==========================\n");

	return 0;
}

int get_all_app_test()
{
	static int num = 0;
	printf("[aul_app_get_all_running_app_info %d test] \n", num++);
	return aul_app_get_all_running_app_info(iterfunc_status, NULL);
}
int get_app_bypid_test()
{
	int pid = 0;
	static int num = 0;
	char buf[MAX_LOCAL_BUFSZ];

	printf("[aul_app_get_appid_bypid %d test] \n", num++);
	pid = atoi(gargv[2]);

	if (aul_app_get_appid_bypid(pid, buf, sizeof(buf)) < 0)
		printf("no such pkg by %d\n", pid);
	else
		printf("pkgname = %s, pid = %d\n", buf, pid);

	return 0;
}

int get_pkg_bypid_test()
{
	int pid = 0;
	static int num = 0;
	char buf[MAX_LOCAL_BUFSZ];

	printf("[aul_app_get_pkgid_bypid %d test] \n", num++);
	pid = atoi(gargv[2]);

	if (aul_app_get_pkgid_bypid(pid, buf, sizeof(buf)) < 0)
		printf("no such pkg by %d\n", pid);
	else
		printf("pkgname = %s, pid = %d\n", buf, pid);

	return 0;
}

int open_file_test()
{
	static int num = 0;
	printf("[aul_open_file %d test] %s \n", num++, gargv[2]);
	return aul_open_file(gargv[2]);
}

int open_content_test()
{
	static int num = 0;
	printf("[aul_open_content %d test] %s \n", num++, gargv[2]);
	return aul_open_content(gargv[2]);
}

int get_defapp_test()
{
	static int num = 0;
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	printf("[aul_get_defapp_from_mime %d test] %s \n", num++, gargv[2]);
	ret = aul_get_defapp_from_mime(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> defapp name = %s\n", buf);
	return ret;
}

int set_defapp_test()
{
	static int num = 0;
	int ret;
	printf("[aul_set_defapp_with_mime %d test] %s %s\n", num++, gargv[2],
	       gargv[3]);
	ret = aul_set_defapp_with_mime(gargv[2], gargv[3]);
	return ret;
}

int get_mime_file_test()
{
	static int num = 0;
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	printf("[aul_get_mime_from_file %d test] %s \n", num++, gargv[2]);
	ret = aul_get_mime_from_file(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> mime type = %s\n", buf);
	return ret;
}

int get_mime_content_test()
{
	static int num = 0;
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	printf("[aul_get_mime_from_content %d test] %s \n", num++, gargv[2]);
	ret = aul_get_mime_from_content(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> mime type = %s\n", buf);
	return ret;
}

int aul_get_mime_icon_test()
{
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	ret = aul_get_mime_icon(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> mimetype %s : iconname = %s\n", gargv[2], buf);
	return ret;
}

int aul_get_mime_description_test()
{
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	ret = aul_get_mime_description(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> mimetype %s : description = %s\n", gargv[2], buf);
	return ret;
}

int aul_get_mime_extension_test()
{
	int ret;
	char buf[MAX_LOCAL_BUFSZ];
	ret = aul_get_mime_extension(gargv[2], buf, sizeof(buf));
	if (ret >= 0)
		printf("==> mimetype %s : extension = %s\n", gargv[2], buf);
	return ret;
}

static void print_menu_db_info(const app_info_from_db *info)
{
	if (info == NULL) {
		printf("pkg %s no found\n", gargv[2]);
		return;
	}

	printf("\t==========================\n");
	printf("\t appid: %s\n", info->appid);
	printf("\t app_path: %s\n", info->app_path);
	printf("\t is_minst: %d\n", 0);
	printf("\t==========================\n");
}

static int get_pkg_func()
{
	app_info_from_db *info;

	info = _get_app_info_from_db_by_pkgname(gargv[2]);
	print_menu_db_info(info);
	if (info)
		_free_app_info_from_db(info);

	return 0;
}

static char *status_text[] = {
	"STATUS_LAUNCHING",
	"STATUS_CREATED",
	"STATUS_FOCUS",
	"STATUS_VISIBLE",
	"STATUS_BG",
	"STATUS_DYING",
	"STATUS_HOME",
	"STATUS_NORESTART",
	"STATUS_SERVICE",
};

static int get_status_pid()
{
	int ret;
	ret = aul_app_get_status_bypid(apn_pid);

	printf("pid: %d status: %d ", apn_pid, ret);
	if (ret >= STATUS_LAUNCHING && ret <= STATUS_NORESTART)
		printf("(%s)", status_text[ret]);

	printf("\n");

	return 0;
}

static int get_pid()
{
	static int num = 0;

	printf("[aul_app_get_pid %d test] %s \n", num++, gargv[2]);
	return aul_app_get_pid(gargv[2]);;
}

static int update_running_list()
{
	aul_running_list_update(gargv[2], gargv[3], gargv[4]);

	return 0;
}

static int launch_async_test()
{
	static int num = 0;
	int ret = 0;
	bundle *kb = NULL;

	kb = create_internal_bundle(3);
	if (kb == NULL)
		return -1;

	printf("[aul_launch_app_async %d test] %s \n", num++, gargv[2]);

	ret = aul_launch_app_async(gargv[2], kb);

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}
	return ret;
}

static int launch_async_test_for_uid()
{
	static int num = 0;
	int ret = 0;
	bundle *kb = NULL;

	kb = create_internal_bundle(3);
	if (kb == NULL)
		return -1;

	printf("[aul_launch_app_async_for_uid %d test] %s \n", num++, gargv[2]);

	ret = aul_launch_app_async_for_uid(gargv[2], kb, atoi(gargv[3]));

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}
	return ret;
}

static int open_test_for_uid()
{
	static int num = 0;

	printf("[aul_open_app_for_uid %d test] %s \n", num++, gargv[2]);
	return aul_open_app_for_uid(gargv[2], atoi(gargv[3]));
}

static int resume_test_for_uid()
{
	static int num = 0;

	printf("[aul_resume_app_for_uid %d test] %s \n", num++, gargv[2]);
	return aul_resume_app_for_uid(gargv[2], atoi(gargv[3]));
}

static int resume_pid_test_for_uid()
{
	static int num = 0;

	printf("[aul_resume_pid_for_uid %d test] %d \n", num++, apn_pid);
	return aul_resume_pid_for_uid(apn_pid, atoi(gargv[3]));
}

static int term_pid_test_for_uid()
{
	static int num = 0;

	printf("[aul_terminate_pid_for_uid %d test] %d \n", num++, apn_pid);
	return aul_terminate_pid_for_uid(apn_pid, atoi(gargv[3]));
}

static int term_pid_async_test_for_uid()
{
	static int num = 0;

	printf("[aul_terminate_pid_async_for_uid %d test] %d \n", num++, apn_pid);
	return aul_terminate_pid_async_for_uid(apn_pid, atoi(gargv[3]));
}

static int get_allpkg_test_for_uid()
{
	static int num = 0;

	printf("[aul_app_get_running_app_info_for_uid %d test] \n", num++);
	return aul_app_get_running_app_info_for_uid(iterfunc, NULL, atoi(gargv[3]));
}

static int get_all_app_test_for_uid()
{
	static int num = 0;

	printf("[aul_app_get_all_running_app_info_for_uid %d test] \n", num++);
	return aul_app_get_all_running_app_info_for_uid(iterfunc_status, NULL, atoi(gargv[2]));
}

static int get_status_pid_for_uid()
{
	int ret;

	ret = aul_app_get_status_bypid_for_uid(apn_pid, atoi(gargv[3]));

	printf("pid: %d uid: %d status: %d", apn_pid, atoi(gargv[3]), ret);
	if (ret >= STATUS_LAUNCHING && ret <= STATUS_NORESTART)
		printf("(%s)", status_text[ret]);
	printf("\n");

	return 0;
}

static int get_pid_for_uid()
{
	static int num = 0;

	printf("[aul_app_get_pid_for_uid %d test] %s \n", num++, gargv[2]);
	return aul_app_get_pid_for_uid(gargv[2], atoi(gargv[3]));
}

static int pause_test_for_uid()
{
	static int num = 0;

	printf("[aul_pause_app_for_uid %d test] %s \n", num++, gargv[2]);
	return aul_pause_app_for_uid(gargv[2], atoi(gargv[3]));
}

static int pause_pid_test_for_uid()
{
	static int num = 0;

	printf("[aul_pause_pid_for_uid %d test] %d \n", num++, apn_pid);
	return aul_pause_pid_for_uid(apn_pid, atoi(gargv[3]));
}

static int term_pid_sync_test()
{
	static int num = 0;

	printf("[aul_terminate_pid_sync %d test] %d \n", num++, apn_pid);
	return aul_terminate_pid_sync(apn_pid);
}

static int term_pid_sync_test_for_uid()
{
	static int num = 0;

	printf("[aul_terminate_pid_sync_for_uid %d test] %d \n", num++, apn_pid);
	return aul_terminate_pid_sync_for_uid(apn_pid, atoi(gargv[3]));
}

static int get_status_test(void)
{
	static int num;
	int ret;

	printf("[aul_app_get_status %d test] %s \n", num++, gargv[2]);

	ret = aul_app_get_status(gargv[2]);
	printf("appid: %s, status: %d", gargv[2], ret);
	if (ret >= STATUS_LAUNCHING && ret <= STATUS_NORESTART)
		printf("(%s)", status_text[ret]);
	printf("\n");

	return 0;
}

static int get_status_test_for_uid(void)
{
	static int num;
	int ret;

	printf("[aul_app_get_status %d test] %s \n", num++, gargv[2]);

	ret = aul_app_get_status_for_uid(gargv[2], atoi(gargv[3]));
	printf("appid: %s, uid: %d, status: %d", gargv[2], atoi(gargv[3]), ret);
	if (ret >= STATUS_LAUNCHING && ret <= STATUS_NORESTART)
		printf("(%s)", status_text[ret]);
	printf("\n");

	return 0;
}

static int test_regex()
{
	char *token;
	char mime[MAX_LOCAL_BUFSZ];
	char *saveptr;

	INIT_PERF(NULL);

	printf("=======================\n");

	token = strtok_r(gargv[2], " \t\n,.()", &saveptr);
	if (aul_get_mime_from_content(token, mime, sizeof(mime)) == AUL_R_OK)
		printf("found %s %s\n", mime, token);

	while (token) {
		token = strtok_r(NULL, " \t\n,()", &saveptr);
		if (aul_get_mime_from_content(token, mime, sizeof(mime)) ==
		    AUL_R_OK)
			printf("found %s %s\n", mime, token);
	}

	PERF("======= parse end =====\n");
	return 0;
}

int reload_appinfo(void)
{
	return aul_reload_appinfo();
}

static test_func_t test_func[] = {
	{"launch", launch_test, "aul_launch_app test",
		"[usage] launch <pkgname> <key1> <val1> <key2> <val2> ..."},
	{"launch_for_uid", launch_test_for_uid,
		"launch with uid test",	"[usage] launch_for_uid <appid> <uid>"},
	{"open", open_test, "aul_open_app test",
		"[usage] open <pkgname>" },
	{"resume", resume_test, "aul_resume_app test",
		"[usage] resume <pkgname>" },
	{"resume_pid", resume_pid_test, "aul_resume_pid test",
		"[usage] resume_pid <pid>" },
	{"term_pid", term_pid_test, "aul_terminate_pid test",
		"[usage] term_pid <pid>" },
	{"term_req_pid", term_req_pid_test, "aul_subapp_terminate_request_pid test",
		"[usage] term_req_pid <pid>" },
	{"term_pid_without_restart", term_pid_without_restart_test, "aul_terminate_pid_without_restart test",
		"[usage] term_pid_without_restart <pid>" },
	{"term_bgapp", term_bgapp_pid_test, "aul_terminate_bgapp_pid test",
		"[usage] term_bgapp <pid>" },
	{"dbuslaunch", dbus_launch_test, "launch by dbus auto activation",
		"[usage] term_pid <pid>" },
	{"all", all_test, "test based on predefine scenario",
		"[usage] all <pkgname>"},
	{"is_run", is_run_test, "aul_is_running test",
		"[usage] is_run <pkgname>"},
	{"getallpkg", get_allpkg_test, "aul_app_get_running_app_info test",
		"[usage] getallpkg all"},
	{"getallappstatus", get_all_app_test, "aul_app_get_all_running_app_info test",
		"[usage] getallappstatus "},
	{"get_app_bypid", get_app_bypid_test, "aul_app_get_appid_bypid test",
		"[usage] get_app_bypid <pid>"},
	{"get_pkg_bypid", get_pkg_bypid_test, "aul_app_get_pkgid_bypid test",
		"[usage] get_pkg_bypid <pid>"},
	{"open_file", open_file_test, "aul_open_file test",
		"[usage] open_file <filename>"},
	{"open_content", open_content_test, "aul_open_content test",
		"[usage] open_content <content>"},
	{"get_defapp_mime", get_defapp_test, "aul_get_defapp_from_mime test",
		"[usage] get_defapp_mime <mime_type>"},
	{"set_defapp_mime", set_defapp_test, "aul_set_defapp_with_mime test",
		"[usage] set_defapp_mime <mime_type> <defapp to be set>"},
	{"get_mime_file", get_mime_file_test, "aul_get_mime_from_file test",
		"[usage] get_mime_file <filename>"},
	{"get_mime_content", get_mime_content_test, "aul_get_mime_from_content",
		"[usage] get_mime_content <content>"},
	{"get_mime_icon", aul_get_mime_icon_test, "aul_get_mime_icon test",
		"[usage] get_mime_icon <mimetype>"},
	{"get_mime_desc", aul_get_mime_description_test, "aul_get_mime_description test",
		"[usage] get_mime_desc <mimetype>"},
	{"get_mime_ext", aul_get_mime_extension_test, "aul_get_mime_extension test",
		"[usage] get_mime_ext <mimetype>"},
	{"test_regex", test_regex, "regular expression parser test",
		"[usage] test_regex <full text>"},
	{"getpkg", get_pkg_func, "get package",
		"[usage] getpkg <pkgname>"},
	{"pause", pause_test, "aul_pause_app test",
		"[usage] pause <pkgname>" },
	{"pause_pid", pause_pid_test, "aul_pause_pid test",
		"[usage] pause_pid <pid>" },
	{"update_list", update_running_list, "update running list",
		"[usage] update_list <appid> <app_path> <pid>"},
	{"reload", reload_appinfo, "reload appinfo table",
		"[usage] reload"},
	{"get_status_pid", get_status_pid, "aul_app_get_status_bypid test",
		"[usage] get_status_pid <pid>"},
	{"get_pid", get_pid, "aul_app_get_pid test",
		"[usage] get_pid <appid>"},
	{"launch_async", launch_async_test, "aul_launch_app_async test",
		"[usage] launch_async <appid> <key1> <val1> <key2> <val2> ..."},
	{"launch_async_for_uid", launch_async_test_for_uid, "aul_launch_app_async_for_uid test",
		"[usage] launch_async_for_uid <appid> <uid> <key1> <val1> <key2> <val2> ..."},
	{"open_for_uid", open_test_for_uid, "aul_open_app_for_uid test",
		"[usage] open_for_uid <appid> <uid>"},
	{"resume_for_uid", resume_test_for_uid, "aul_resume_app_for_uid test",
		"[usage] resume_for_uid <appid> <uid>"},
	{"resume_pid_for_uid", resume_pid_test_for_uid, "aul_resume_pid_for_uid test",
		"[usage] resume_pid_for_uid <pid> <uid>"},
	{"term_pid_for_uid", term_pid_test_for_uid, "aul_terminate_pid_for_uid test",
		"[usage] term_pid_for_uid <pid> <uid>"},
	{"term_pid_async_for_uid", term_pid_async_test_for_uid, "aul_terminate_pid_async_for_uid test",
		"[usage] term_pid_async_for_uid <pid> <uid>"},
	{"getallpkg_for_uid", get_allpkg_test_for_uid, "aul_app_get_running_app_info_for_uid test",
		"[usage] getallpkg_for_uid all <uid>"},
	{"getallappstatus_for_uid", get_all_app_test_for_uid, "aul_app_get_all_running_app_info_for_uid test",
		"[usage] getallappstatus_for_uid <uid>"},
	{"get_status_pid_for_uid", get_status_pid_for_uid, "aul_app_get_status_bypid_for_uid test",
		"[usage] get_status_pid_for_uid <pid> <uid>"},
	{"get_pid_for_uid", get_pid_for_uid, "aul_app_get_pid_for_uid test",
		"[usage] get_pid_for_uid <appid> <uid>"},
	{"pause_for_uid", pause_test_for_uid, "aul_pause_app_for_uid test",
		"[usage] pasue_for_uid <appid> <uid>"},
	{"pause_pid_for_uid", pause_pid_test_for_uid, "aul_pause_pid_for_uid test",
		"[usage] pause_pid_for_uid <pid> <uid>"},
	{"term_pid_sync", term_pid_sync_test, "aul_terminate_pid_sync test",
		"[usage] term_pid_sync <pid>"},
	{"term_pid_sync_for_uid", term_pid_sync_test_for_uid, "aul_terminate_pid_sync_for_uid test",
		"[usage] term_pid_sync_for_uid <pid> <uid>"},
	{"get_status", get_status_test, "aul_app_get_status test",
		"[usage] get_status <appid>"},
	{"get_status_for_uid", get_status_test_for_uid, "aul_app_get_status_for_uid test",
		"[usage] get_status_for_uid <appid> <uid>"},
};

int callfunc(char *testname)
{
	test_func_t *tmp;
	int res;
	int i;

	for (i = 0; i < sizeof(test_func) / sizeof(test_func_t); i++) {
		tmp = &test_func[i];
		if (strcmp(testname, tmp->name) == 0) {
			res = tmp->func();
			if (strcmp(testname, "all")) {
				if (res < 0)
					printf("... test failed\n");
				else
					printf("... test successs ret = %d\n",
					       res);
			}
		}
	}
	return 0;
}

int dead_tracker(int pid, void *data)
{
	printf("[DEAD] pid = %d dead\n", pid);
	return 0;
}

void print_usage(char *progname)
{
	test_func_t *tmp;
	int i;

	printf("[usage] %s <cmd> ...\n", progname);
	printf(" - available cmd list\n");

	for (i = 0; i < sizeof(test_func) / sizeof(test_func_t); i++) {
		tmp = &test_func[i];
		printf("\t%s : %s\n", tmp->name, tmp->desc);
		printf("\t\t%s\n", tmp->usage);
	}

	printf("[note] getpkg/setpkg/delpkg/init_defapp_mime/reload "
		"cmd is internal purpose\n");
}

static gboolean run_func(void *data)
{
	callfunc(cmd);

	if (strcmp(cmd, "launch_res") == 0 || strcmp(cmd, "all") == 0
	    || strcmp(cmd, "dbuslaunch") == 0
	    || strcmp(cmd, "open_svc_res") == 0)
		return 0;
	else
		g_main_loop_quit(mainloop);

	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		print_usage(argv[0]);
		exit(0);
	}

	cmd = argv[1];
	gargc = argc;
	gargv = argv;
	if (argv[2])
		apn_pid = atoi(argv[2]);

	aul_launch_init(NULL, NULL);

	/*aul_listen_app_dead_signal(dead_tracker,NULL); */
	/*aul_listen_app_dead_signal(NULL,NULL); */

	g_idle_add(run_func, NULL);

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		printf("failed to create glib main loop\n");
		exit(EXIT_FAILURE);
	}
	g_main_loop_run(mainloop);

	return 0;
}

/* vi: set ts=8 sts=8 sw=8: */

