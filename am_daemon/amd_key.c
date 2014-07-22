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

#include <aul.h>
#include <glib.h>
#include <stdlib.h>

#include "amd_config.h"
#include "simple_util.h"
#include "app_sock.h"
#include "launch.h"

GSList *key_pid_list = NULL;

int _register_key_event(int pid)
{
	int *pid_data;
	GSList *entry;

	pid_data = malloc(sizeof(int));
	*pid_data = pid;

	key_pid_list = g_slist_prepend(key_pid_list, pid_data);

	_D("===key stack===");

	for (entry = key_pid_list; entry; entry = entry->next) {
		if (entry->data) {
			pid_data = (int *) entry->data;
			_D("pid : %d",*pid_data);
		}
	}

	return 0;
}

int _unregister_key_event(int pid)
{
	GSList *entry;
	int *pid_data;

	for (entry = key_pid_list; entry;) {
		if (entry->data) {
			pid_data = (int *) entry->data;
			entry = entry->next;
			if(pid == *pid_data) {
				key_pid_list = g_slist_remove(key_pid_list, pid_data);
				free(pid_data);
			}
		}
	}

	_D("===key stack===");

	for (entry = key_pid_list; entry; entry = entry->next) {
		if (entry->data) {
			pid_data = (int *) entry->data;
			_D("pid : %d",*pid_data);
		}
	}

	return 0;
}

