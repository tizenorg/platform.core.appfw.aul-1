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
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <glib.h>

#include "aul.h"

#define ROOT_UID 0
#define TMP_FILE "/tmp/.testpkg"

static char **gargv;
static int gargc;
bundle *kb = NULL;
static int debugFlag = 0;

static GMainLoop *mainloop = NULL;

static bundle *create_internal_bundle()
{
	bundle *kb;

	kb = bundle_create();
	bundle_add(kb, AUL_K_DEBUG, "1");
	return kb;
}

int launch(int debug_option)
{
	int pid;

	if(!debug_option)
		pid = aul_open_app(gargv[1]);
	else {
		kb = create_internal_bundle();
		if (NULL == kb) {
			printf("bundle creation fail\n");
			return -1;
		}
		pid = aul_launch_app(gargv[1], kb);
	}
	return pid;
}

void print_usage(char *progname)
{
	printf("[usage] %s <appid> [-d]\n",
	       progname);
}

static int __launch_app_dead_handler(int pid, void *data)
{
	int listen_pid = (intptr_t)data;

	if(listen_pid == pid)
		g_main_loop_quit(mainloop);

	return 0;
}

static gboolean run_func(void *data)
{
	int pid;
	const char *str;

	if ((pid = launch(debugFlag)) > 0)
		printf("... successfully launched\n");
	else
		printf("... launch failed\n");

	if (kb) {
		str = bundle_get_val(kb, "__LAUNCH_APP_MODE__");

		if (str && strcmp(str, "SYNC") == 0 )
			aul_listen_app_dead_signal(__launch_app_dead_handler, (void *)(intptr_t)pid);
		else
			g_main_loop_quit(mainloop);

		bundle_free(kb);
		kb = NULL;
	} else {
		g_main_loop_quit(mainloop);
	}


	return TRUE;
}


int main(int argc, char **argv)
{
	if ((argc < 2)||(argc > 3)) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	gargc = argc;
	gargv = argv;

	if(argc == 3) {
		if( (strcmp(argv[2],"-d")  != 0 ) && (strcmp(argv[1],"-d")  != 0 ) ) {
			printf("additionnal argument should be -d to enable debugging\n");
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
		debugFlag = 1;
	}
	aul_launch_init(NULL, NULL);

	g_idle_add(run_func, NULL);

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		printf("failed to create glib main loop\n");
		exit(EXIT_FAILURE);
	}
	g_main_loop_run(mainloop);

	return 0;
}

