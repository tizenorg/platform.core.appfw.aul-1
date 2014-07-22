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
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include "aul.h"

#define ROOT_UID 0
#define TMP_FILE "/tmp/.testpkg"

static char **gargv;
static int gargc;
bundle *kb = NULL;


static bundle *create_internal_bundle(int start)
{
	bundle *kb;
	int i;
	char arg[1024] = {0, };
	char* val_array[128];

	kb = bundle_create();
	for (i = start; i < gargc - 1; i++) {
		if ((i + 1) > gargc - 1)
			bundle_add(kb, gargv[i], " ");
		else {
			int j = 1;
			strncpy(arg, gargv[i + 1], 1023);
			val_array[0] = strtok(arg,",");
			while(1)
			{
				val_array[j] = strtok(NULL,",");
				if(val_array[j] == NULL)
					break;
				j++;
			}
			if(j==1)
				bundle_add(kb, gargv[i], gargv[i + 1]);
			else if(j>1)
				bundle_add_str_array(kb, gargv[i],
					(const char**)val_array, j);
		}
	}

	return kb;
}

int launch()
{
	int pid = -1;

	kb = create_internal_bundle(2);
	if (NULL == kb) {
		printf("bundle creation fail\n");
		return -1;
	}

	pid = aul_open_app(gargv[1]);
	return pid;
}

void print_usage(char *progname)
{
	printf("[usage] %s <appid>\n",
	       progname);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	gargc = argc;
	gargv = argv;

	aul_launch_init(NULL, NULL);
	int pid = -1;

	if ((pid = launch()) > 0) {
		printf("... successfully launched\n");
	} else {
		printf("... launch failed\n");
	}

	if (kb) {
		bundle_free(kb);
		kb = NULL;
	}

	return 0;
}

