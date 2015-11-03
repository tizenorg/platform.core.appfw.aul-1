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
#include <glib.h>

#include <pkgmgr-info.h>
#include <bundle.h>

#include "aul.h"

static GMainLoop *mainloop = NULL;

struct launch_arg {
	char appid[256];
	char **argv;
	int argc;
	int flag_debug;
	int sync;
} launch_arg;

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
		g_main_loop_quit(mainloop);

	return 0;
}

static gboolean run_func(void *data)
{
	int pid;
	bundle *kb;
	struct launch_arg *launch_arg_data = (struct launch_arg *)data;

	kb = _create_internal_bundle(launch_arg_data);
	pid = aul_launch_app((char *)launch_arg_data->appid, kb);

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}

	if (pid > 0) {
		printf("... successfully launched pid = %d with debug %d\n",
				pid, launch_arg_data->flag_debug);
		if (launch_arg_data->sync) {
			aul_listen_app_dead_signal(__launch_app_dead_handler, (void *)(intptr_t)pid);
			return FALSE;
		}
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
			"   -d                        --debug             Activate debug mode\n"
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

	printf("\tApplication List for user %lu\n", (long)getuid());
	printf("\tUser's Application \n");
	printf("\t Name \t AppID \n");
	printf("\t=================================================\n");
	if (pkgmgrinfo_appinfo_get_usr_installed_list(__appinfo_list_cb,
				getuid(), NULL) != PMINFO_R_OK)
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
		aul_terminate_pid(info->pid);
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
				getuid())) {
		printf("Failed to get filter count\n");
		pkgmgrinfo_appinfo_filter_destroy(filter);
		return -1;
	}

	pkgmgrinfo_appinfo_filter_destroy(filter);

	return is_installed;
}

int main(int argc, char **argv)
{
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
		{ "debug", no_argument, 0, 'd' },
		{ 0, 0, 0, 0 }
	};
	memset(&args, 0, sizeof(struct launch_arg));

	do {
		next_opt = getopt_long(argc,
				argv,
				"hlSs:k:t:r:d",
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
			if (list_app()) {
				printf("Fail to display the list of "
						"installed applications\n");
				return -1;
			}
			disp_list = true;
			break;
		case 'S':
			if (disp_run_list)
				break;
			printf("\t appId (PID)\n");
			if (aul_app_get_running_app_info(__iterfunc_status,
						NULL)) {
				printf("Fail to display the list of "
						"Running applications\n");
				return -1;
			}
			disp_run_list = true;
			break;
		case 's':
		case 'k':
		case 't':
		case 'r':
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
		case '?':
			break;
		case -1:
			break;
		default:
			print_usage(argv[0]);
			break;
		}
	} while (next_opt != -1);

	if (argc == 1)
		print_usage(argv[0]);

	if (optind < argc) {
		args.argc = argc - optind;
		args.argv = &argv[optind];
	}
	if ((op == 's') || (op == 'k') || (op == 'r')) {
		if (is_app_installed(args.appid) <= 0) {
			printf("The app with ID: %s is not avaible "
					"for the user %d \n",
					args.appid, getuid());
			return -1;
		}
	}

	if (op == 's') {
		if (strlen(args.appid) <= 0) {
			printf("result: %s\n", "failed");
			return -1;
		}
		aul_launch_init(NULL, NULL);
		g_idle_add(run_func, args.appid);
		mainloop = g_main_loop_new(NULL, FALSE);
		if (!mainloop) {
			printf("failed to create glib main loop\n");
			exit(EXIT_FAILURE);
		}
		g_main_loop_run(mainloop);
		return 0;
	} else if (op == 'k') {
		is_running = aul_app_is_running(args.appid);
		if (true == is_running) {
			aul_app_get_running_app_info(__iterfunc_kill,
					args.appid);
		} else {
			printf("result: %s\n", "App isn't running");
			return 1;
		}
	} else if (op == 't') {
		is_running = aul_app_is_running(args.appid);
		if (true == is_running) {
			aul_app_get_running_app_info(__iterfunc_term,
					args.appid);
		} else {
			printf("result: %s\n", "App isn't running");
			return 1;
		}
	} else if (op == 'r') {
		is_running = aul_app_is_running(args.appid);
		if (true == is_running) {
			printf("result: %s\n", "running");
			return 0;
		} else {
			printf("result: %s\n", "not running");
			return 1;
		}
	}

	return 0;
}
