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

#include "aul.h"

#define DLP_K_ATTACH_ARG "__DLP_ATTACH_ARG__"
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
		if ((i + 1) > (argc - 1))
			bundle_add(b, argv[1], " ");
		else if (argv[i] && strcmp(argv[i], AUL_K_SDK) == 0)
			bundle_add(b, AUL_K_SDK, argv[i + 1]);
		else if (argv[i] && strcmp(argv[i], DLP_K_ATTACH_ARG) == 0) {
			arg[0] = strtok(argv[i + 1], ",");

			cnt = 1;
			while ((arg[cnt] = strtok(NULL, ",")) != NULL)
				cnt++;

			bundle_add(b, SDK_ATTACH, DLP_K_ATTACH_ARG);
			bundle_add_str_array(b, DLP_K_ATTACH_ARG, NULL, cnt);

			for (j = 0; j < cnt; j++)
				bundle_set_str_array_element(b, DLP_K_ATTACH_ARG, j, arg[j]);
		}
	}

	return b;
}

static void print_usage(char *progname)
{
	printf("[usage] %s [appid] %s %s %s --attach,:[port],[pid]\n",
			progname, AUL_K_SDK, SDK_ATTACH, DLP_K_ATTACH_ARG);
	printf("ex) $ %s [appid] %s %s %s --attach,:10003,1234\n",
			progname, AUL_K_SDK, SDK_ATTACH, DLP_K_ATTACH_ARG);
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

	ret = aul_launch_app(argv[1], b);
	if (ret < 0)
		printf("Failed to launch %s\n", argv[1]);

	bundle_free(b);

	return 0;
}
