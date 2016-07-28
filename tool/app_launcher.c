/*
 *  app_launcher
 *
 * Copyright (c) 2014, Intel Corporation.
 *
 * Contact: Baptiste DURAND <baptiste.durand@open.eurogiciel.org>
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
#include <getopt.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <linux/limits.h>
#include <sys/inotify.h>

#include <gio/gio.h>
#include <glib.h>
#include <pkgmgr-info.h>
#include <bundle.h>
#include <bundle_internal.h>
#ifdef TIZEN_FEATURE_DEFAULT_USER
#include <tzplatform_config.h>
#endif

#include "aul.h"
#include "aul_svc.h"
#include "launch.h"

#define AMD_READY ".amd_ready"
#define LAUNCHPAD_PROCESS_POOL_SOCK ".launchpad-process-pool-sock"
#define APP_TYPE_UI "uiapp"
#define APP_TYPE_SERVICE "svcapp"
#ifdef TIZEN_FEATURE_DEFAULT_USER
#define REGULAR_UID_MIN 5000
#endif
#define INOTIFY_BUF (1024 * ((sizeof(struct inotify_event)) + 16))

struct launch_arg {
	char appid[256];
	char **argv;
	int argc;
	int flag_debug;
	int flag_web;
	int sync;
	char op;
};

struct amd_watch {
	int fd;
	int wd;
	GIOChannel *io;
	guint wid;
	char *appid;
	int pid;
};

static GMainLoop *mainloop = NULL;
static uid_t uid;
static int monitoring_dead_signal;
static int monitoring_amd_ready;

static bundle *_create_internal_bundle(struct launch_arg *args)
{
	bundle *b;
	int i;

	if (!args->flag_debug && args->argc < 2)
		return NULL;

	b = bundle_create();
	if (args->flag_debug)
		bundle_add(b, AUL_K_DEBUG, "1");

	for (i = 0; i + 1 < args->argc; i += 2) {
		bundle_add(b, args->argv[i], args->argv[i + 1]);
		if (!strcmp(args->argv[i], "__LAUNCH_APP_MODE__") &&
				!strcmp(args->argv[i + 1], "SYNC"))
			args->sync = 1;
	}

	return b;
}

static int __launch_app_dead_handler(int pid, void *data)
{
	int listen_pid = (intptr_t)data;

	if (listen_pid == pid)
		monitoring_dead_signal = 0;

	if (!monitoring_dead_signal && !monitoring_amd_ready)
		g_main_loop_quit(mainloop);

	return 0;
}

static void __reply_cb_func(bundle *b, int request_code, aul_svc_result_val result, void *data)
{
	char* port = NULL;
	const char* pid_str = NULL;
	int pid = 0;

	bundle_get_str(b, "port", &port);
	pid_str = bundle_get_val(b, AUL_K_CALLEE_PID);
	if (pid_str)
		pid = atoi(pid_str);

	if (port != NULL && strlen(port) > 0) {
		printf("... successfully launched pid = %d with debug 1 port: %s\n",
					pid, port);
	} else {
		printf("... launch failed\n");
	}

	g_main_loop_quit(mainloop);
}

static gboolean run_func(void *data)
{
	int pid;
	bundle *kb;
	struct launch_arg *launch_arg_data = (struct launch_arg *)data;

	kb = _create_internal_bundle(launch_arg_data);

	if (launch_arg_data->op == 'e') {
		if (kb == NULL)
			kb = bundle_create();
		aul_svc_set_loader_id(kb, PAD_LOADER_ID_DIRECT);
	}

	if (!launch_arg_data->flag_web) {
		pid = aul_launch_app_for_uid((char *)launch_arg_data->appid, kb, uid);

		if (kb) {
			bundle_free(kb);
			kb = NULL;
		}

		if (pid > 0) {
			printf("... successfully launched pid = %d with debug %d\n",
					pid, launch_arg_data->flag_debug);
			if (launch_arg_data->sync) {
				aul_listen_app_dead_signal(__launch_app_dead_handler, (void *)(intptr_t)pid);
				monitoring_dead_signal = 1;
				return FALSE;
			}
		} else {
			printf("... launch failed\n");
		}

		g_main_loop_quit(mainloop);
	} else {
		aul_svc_set_operation(kb, AUL_SVC_OPERATION_DEFAULT);
		aul_svc_set_appid(kb, (char *)launch_arg_data->appid);
		pid = aul_svc_run_service_for_uid(kb, 0, __reply_cb_func, (void*)NULL, uid);
		if (pid <= 0) {
			printf("... launch failed\n");
			g_main_loop_quit(mainloop);
		}
	}

	return FALSE;
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

static int __set_appinfo_for_launchpad(bundle *kb, const char *appid)
{
	pkgmgrinfo_appinfo_h handle;
	int ret;
	char *pkgid = NULL;
	char *exec = NULL;
	char *apptype = NULL;
	char *pkgtype = NULL;
	char *component_type = NULL;
	char *root_path = NULL;
	char *api_version = NULL;
	pkgmgrinfo_app_hwacceleration hwacc = PMINFO_HWACCELERATION_OFF;
	const char *hwacc_str = "NOT_USE";
	bool process_pool = false;

	if (kb == NULL)
		return -1;

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, uid, &handle);
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

	if (!component_type || (strcmp(component_type, APP_TYPE_SERVICE) != 0
			&& strcmp(component_type, APP_TYPE_UI) != 0)) {
		ret = -1;
		goto end;
	}

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

	ret = pkgmgrinfo_appinfo_get_root_path(handle, &root_path);
	if (ret != PMINFO_R_OK)
		goto end;

	ret = pkgmgrinfo_appinfo_get_api_version(handle, &api_version);
	if (ret != PMINFO_R_OK)
		goto end;

	bundle_add(kb, AUL_K_APPID, appid);
	bundle_add(kb, AUL_K_HWACC, hwacc_str);
	bundle_add(kb, AUL_K_EXEC, exec);
	bundle_add(kb, AUL_K_APP_TYPE, apptype);
	bundle_add(kb, AUL_K_PKGID, pkgid);
	bundle_add(kb, AUL_K_INTERNAL_POOL, process_pool ? "true" : "false");
	bundle_add(kb, AUL_K_COMP_TYPE, component_type);
	bundle_add(kb, AUL_K_PACKAGETYPE, pkgtype);
	bundle_add(kb, AUL_K_ROOT_PATH, root_path);
	bundle_add(kb, AUL_K_API_VERSION, api_version);

	aul_svc_set_loader_id(kb, PAD_LOADER_ID_DIRECT);

end:
	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return ret;
}

static gboolean __amd_monitor_cb(GIOChannel *io, GIOCondition cond,
		gpointer data)
{
	char buf[INOTIFY_BUF];
	ssize_t len = 0;
	int i = 0;
	struct inotify_event *event;
	char *p;
	int fd = g_io_channel_unix_get_fd(io);
	struct amd_watch *watch = (struct amd_watch *)data;

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return TRUE;

	while (i < len) {
		event = (struct inotify_event *)&buf[i];
		if (event->len) {
			p = event->name;
			if (p && !strcmp(p, AMD_READY)) {
				aul_app_register_pid(watch->appid, watch->pid);
				monitoring_amd_ready = 0;
				return FALSE;
			}
		}
		i += offsetof(struct inotify_event, name) + event->len;
	}

	return TRUE;
}

static void __watch_destroy_cb(gpointer data)
{
	struct amd_watch *watch = (struct amd_watch *)data;

	if (watch == NULL)
		return;

	g_io_channel_unref(watch->io);

	if (watch->appid)
		free(watch->appid);
	if (watch->wd)
		inotify_rm_watch(watch->fd, watch->wd);
	close(watch->fd);
	free(watch);

	if (!monitoring_dead_signal && !monitoring_amd_ready)
		g_main_loop_quit(mainloop);
}

static void __watch_amd_ready(const char *appid, int pid)
{
	char buf[PATH_MAX];
	struct amd_watch *watch;

	snprintf(buf, sizeof(buf), "/run/user/%d", uid);

	watch = (struct amd_watch *)calloc(1, sizeof(struct amd_watch));
	if (watch == NULL)
		return;

	watch->appid = strdup(appid);
	if (watch->appid == NULL) {
		free(watch);
		return;
	}

	watch->pid = pid;

	watch->fd = inotify_init();
	if (watch->fd < 0) {
		free(watch->appid);
		free(watch);
		return;
	}

	watch->wd = inotify_add_watch(watch->fd, buf, IN_CREATE);
	if (watch->wd < 0) {
		close(watch->fd);
		free(watch->appid);
		free(watch);
		return;
	}

	watch->io = g_io_channel_unix_new(watch->fd);
	if (watch->io == 0) {
		inotify_rm_watch(watch->fd, watch->wd);
		close(watch->fd);
		free(watch->appid);
		free(watch);
		return;
	}

	watch->wid = g_io_add_watch_full(watch->io, G_PRIORITY_DEFAULT,
			G_IO_IN, __amd_monitor_cb, watch, __watch_destroy_cb);
	monitoring_amd_ready = 1;
}

static void __register_appinfo(const char *appid, int pid)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "/run/user/%d/%s", uid, AMD_READY);
	if (access(buf, F_OK) == 0) {
		aul_app_register_pid(appid, pid);
		return;
	}

	__watch_amd_ready(appid, pid);
}

static gboolean fast_run_func(void *data)
{
	int pid;
	bundle *kb;
	struct launch_arg *launch_arg_data = (struct launch_arg *)data;

	kb = _create_internal_bundle(launch_arg_data);
	if (kb == NULL)
		kb = bundle_create();

	if (__set_appinfo_for_launchpad(kb, launch_arg_data->appid) < 0) {
		printf("failed to set appinfo\n");
		bundle_free(kb);
		return FALSE;
	}

	pid = app_send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK,
			uid, 0, kb);
	bundle_free(kb);
	if (pid > 0) {
		printf("... successfully launched pid = %d\n", pid);
		__register_appinfo(launch_arg_data->appid, pid);
		if (launch_arg_data->sync) {
			aul_listen_app_dead_signal(__launch_app_dead_handler,
					(void *)(intptr_t)pid);
			monitoring_dead_signal = 1;
		}

		if (monitoring_dead_signal || monitoring_amd_ready)
			return FALSE;
	} else {
		printf("... launch failed\n");
	}

	g_main_loop_quit(mainloop);

	return FALSE;
}

static void print_usage(char *program)
{
	printf("Usage : %s [ OPTIONS... ] [ ARGS... ]\n", program);
	printf(
			"   -h                        --help              Display this usage information.\n"
			"   -l                        --list              Display installed apps list\n"
			"   -S                        --status            Display running apps list\n"
			"   -s [tizen application ID] --start             Launch widget with tizen application ID\n"
			"   -k [tizen application ID] --kill              Kill widget with tizen application ID\n"
			"   -t [tizen application ID] --terminate         Terminate widget with tizen application ID\n"
			"   -r [tizen application ID] --is-running        Check whether application is running by tizen application ID,\n"
			"                                                 If widget is running, 0(zero) will be returned.\n"
			"   -f [tizen application ID] --fast-start        Fast launch app with tizen application ID\n"
			"   -e [tizen application ID] --direct-start      Direct Launch app with tizen application ID\n"
			"   -d                        --debug             Activate debug mode\n"
			"   -w                        --web-debug         Activate web debug mode. Use only for webapps\n"
			"   -u [uid]                  --user              Specify user. Use with other commands.\n"
	      );
}

static int __appinfo_list_cb(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *label;
	char *appid;

	if (pkgmgrinfo_appinfo_get_label(handle, &label))
		label = "";

	if (pkgmgrinfo_appinfo_get_appid(handle, &appid)) {
		printf("Failed to get appid\n");
		return -1;
	}

	printf("\t'%s'\t '%s'\n", label, appid);

	return 0;
}

static int list_app(void)
{
	int ret = 0;

	printf("\tApplication List for user %lu\n", (long)uid);
	printf("\tUser's Application \n");
	printf("\t Name \t AppID \n");
	printf("\t=================================================\n");
	if (pkgmgrinfo_appinfo_get_usr_installed_list(__appinfo_list_cb,
				uid, NULL) != PMINFO_R_OK)
		ret = -1;
	printf("\t=================================================\n");
	return ret;
}

static int __iterfunc_status(const aul_app_info *info, void *data)
{
	printf("\t  %s (%d)\n", info->appid, info->pid);
	return 0;
}

static int __iterfunc_kill(const aul_app_info *info, void *data)
{
	if (!data)
		return 0;
	if (strcmp(info->appid, data) == 0) {
		aul_kill_pid(info->pid);
		printf("\t Kill appId: %s (%d)\n", info->appid, info->pid);
	}
	return 0;
}

static int __iterfunc_term(const aul_app_info *info, void *data)
{
	if (!data)
		return 0;
	if (strcmp(info->appid, data) == 0) {
		aul_terminate_pid_for_uid(info->pid, uid);
		printf("\t Terminate appId: %s (%d)\n", info->appid, info->pid);
	}
	return 0;
}

static int is_app_installed(char *appid)
{
	int is_installed = 0;
	pkgmgrinfo_appinfo_filter_h filter;

	if (pkgmgrinfo_appinfo_filter_create(&filter)) {
		printf("Failed to create filter\n");
		return -1;
	}

	if (pkgmgrinfo_appinfo_filter_add_string(filter,
				PMINFO_APPINFO_PROP_APP_ID, appid)) {
		printf("Failed to add filter string\n");
		pkgmgrinfo_appinfo_filter_destroy(filter);
		return -1;
	}

	if (pkgmgrinfo_appinfo_usr_filter_count(filter, &is_installed,
				uid)) {
		printf("Failed to get filter count\n");
		pkgmgrinfo_appinfo_filter_destroy(filter);
		return -1;
	}

	pkgmgrinfo_appinfo_filter_destroy(filter);

	return is_installed;
}

int main(int argc, char **argv)
{
	char path[PATH_MAX];
	bool disp_help = false;
	bool disp_list = false;
	bool disp_run_list = false;
	bool is_running;
	int next_opt;
	int opt_idx = 0;
	char op = '\0';
	struct launch_arg args;
	static struct option long_options[] = {
		{ "help", no_argument, 0, 'h' },
		{ "list", no_argument, 0, 'l' },
		{ "status", no_argument, 0, 'S' },
		{ "start", required_argument, 0, 's' },
		{ "args", required_argument, 0, 'a' },
		{ "kill", required_argument, 0, 'k' },
		{ "terminate", required_argument, 0, 't' },
		{ "is-running", required_argument, 0, 'r' },
		{ "fast-launch", required_argument, 0, 'f' },
		{ "direct-launch", required_argument, 0, 'e' },
		{ "debug", no_argument, 0, 'd' },
		{ "web-debug", no_argument, 0, 'w' },
		{ "user", required_argument, 0, 'u' },
		{ 0, 0, 0, 0 }
	};
	memset(&args, 0, sizeof(struct launch_arg));

	uid = getuid();

	do {
		next_opt = getopt_long(argc,
				argv,
				"hlSs:k:t:r:f:e:dwu:",
				long_options,
				&opt_idx);

		switch (next_opt) {
		case 'h':
			if (!disp_help) {
				print_usage(argv[0]);
				disp_help = true;
			}
			break;
		case 'l':
			if (disp_list)
				break;

			op = next_opt;
			disp_list = true;
			break;
		case 'S':
			if (disp_run_list)
				break;
			op = next_opt;
			disp_run_list = true;
			break;
		case 's':
		case 'k':
		case 't':
		case 'r':
		case 'f':
		case 'e':
			if (strlen(optarg) > 255) {
				print_usage(argv[0]);
				return -1;
			} else {
				strncpy(args.appid, optarg, sizeof(args.appid) - 1);
			}
			op = next_opt;
			break;
		case 'd':
			args.flag_debug = 1;
			break;
		case 'w':
			args.flag_debug = 1;
			args.flag_web = 1;
			break;
		case '?':
			break;
		case -1:
			break;
		case 'u':
			uid = atoi(optarg);
			break;
		default:
			print_usage(argv[0]);
			break;
		}
	} while (next_opt != -1);

	if (argc == 1)
		print_usage(argv[0]);

#ifdef TIZEN_FEATURE_DEFAULT_USER
	if (uid < REGULAR_UID_MIN)
		uid = tzplatform_getuid(TZ_SYS_DEFAULT_USER);
#endif

	if (op == 'S') {
		printf("\t appId (PID)\n");
		if (aul_app_get_running_app_info_for_uid(__iterfunc_status,
					NULL, uid)) {
			printf("Fail to display the list of "
					"Running applications\n");
			return -1;
		}
	} else if (op == 'l') {
		if (list_app()) {
			printf("Fail to display the list of "
					"installed applications\n");
			return -1;
		}
	}

	if (optind < argc) {
		args.argc = argc - optind;
		args.argv = &argv[optind];
	}
	if ((op == 's') || (op == 'k') || (op == 'r') || (op == 'f') || (op == 'e')) {
		if (is_app_installed(args.appid) <= 0) {
			printf("The app with ID: %s is not avaible "
					"for the user %d \n",
					args.appid, uid);
			return -1;
		}
	}

	if ((op == 's') || (op == 'e')) {
		if (strlen(args.appid) <= 0) {
			printf("result: %s\n", "failed");
			return -1;
		}
		args.op = op;
		g_idle_add(run_func, args.appid);
		mainloop = g_main_loop_new(NULL, FALSE);
		if (!mainloop) {
			printf("failed to create glib main loop\n");
			exit(EXIT_FAILURE);
		}
		g_main_loop_run(mainloop);
		return 0;
	} else if (op == 'k') {
		is_running = aul_app_is_running_for_uid(args.appid, uid);
		if (true == is_running) {
			aul_app_get_running_app_info_for_uid(__iterfunc_kill,
					args.appid, uid);
		} else {
			printf("result: %s\n", "App isn't running");
			return 1;
		}
	} else if (op == 't') {
		is_running = aul_app_is_running_for_uid(args.appid, uid);
		if (true == is_running) {
			aul_app_get_running_app_info_for_uid(__iterfunc_term,
					args.appid, uid);
		} else {
			printf("result: %s\n", "App isn't running");
			return 1;
		}
	} else if (op == 'r') {
		is_running = aul_app_is_running_for_uid(args.appid, uid);
		if (true == is_running) {
			printf("result: %s\n", "running");
			return 0;
		} else {
			printf("result: %s\n", "not running");
			return 1;
		}
	} else if (op == 'f') {
		if (strlen(args.appid) <= 0) {
			printf("result: failed\n");
			return -1;
		}

		snprintf(path, sizeof(path), "/run/user/%d/%s",
						uid, AMD_READY);
		if (access(path, F_OK) == 0)
			g_idle_add(run_func, args.appid);
		else
			g_idle_add(fast_run_func, args.appid);

		mainloop = g_main_loop_new(NULL, FALSE);
		if (!mainloop) {
			printf("failed to create glib main loop\n");
			exit(EXIT_FAILURE);
		}
		g_main_loop_run(mainloop);
	}

	return 0;
}
