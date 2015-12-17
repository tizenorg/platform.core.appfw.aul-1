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

#pragma once

#include <unistd.h>
#include <sys/types.h>

#define USE_ENGINE(engine) setenv("ELM_ENGINE", engine, 1);

#define AUL_UTIL_PID -2

#define MAX_PACKAGE_STR_SIZE 512
#define MAX_PACKAGE_APP_PATH_SIZE 512
#define MAX_RUNNING_APP_INFO 512

#define GSLIST_FOREACH_SAFE(list, l, l_next)   \
	for (l = list,                            \
			l_next = g_slist_next(l);       \
			l;                              \
			l = l_next,                     \
			l_next = g_slist_next(l))

int _add_app_status_info_list(char *appid, int pid, uid_t uid);
int _update_app_status_info_list(int pid, int status, uid_t uid);
int _remove_app_status_info_list(int pid, uid_t uid);


