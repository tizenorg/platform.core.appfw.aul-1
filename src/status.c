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

#define _GNU_SOURCE
#include <stdlib.h>

#include <aul.h>
#include <bundle.h>
#include <bundle_internal.h>

#include "aul_util.h"
#include "app_sock.h"
#include "aul_api.h"
#include "launch.h"

typedef struct _app_status_cb_info_t {
	int (*handler) (int status, void *data);
	void *data;
	struct _app_status_cb_info_t *next;
} app_status_cb_info_t;

app_status_cb_info_t *app_status_cb = NULL;

static int app_status = STATUS_LAUNCHING;

API int aul_status_update(int status)
{
	int ret;
	app_status_cb_info_t *cb = app_status_cb;

	app_status = status;

	ret = __app_send_raw_with_noreply(AUL_UTIL_PID, APP_STATUS_UPDATE, (unsigned char *)&status, sizeof(status));

	if (!ret) {
		while (cb) {
			if (cb->handler) {
				if (cb->handler(app_status, cb->data) < 0)
					aul_remove_status_local_cb(cb->handler, cb->data);
			}

			cb = cb->next;
		}
	}

	return ret;
}

API  int aul_app_get_status_bypid(int pid)
{
	int ret;

	if (pid == getpid())
		return app_status;

	ret = __app_send_raw(AUL_UTIL_PID, APP_GET_STATUS, (unsigned char *)&pid, sizeof(pid));

	return ret;
}

API int aul_add_status_local_cb(int (*func)(int status, void *data), void *data)
{
	app_status_cb_info_t *cb = app_status_cb;

	if (func == NULL)
		return -1;

	/* check known callback */
	while (cb) {
		if (cb && cb->handler == func && cb->data == data) {
			/* already in list */
			return 0;
		}
		cb = cb->next;
	}

	cb = (app_status_cb_info_t *)malloc(sizeof(app_status_cb_info_t));
	if (cb == NULL)
		return -1;

	cb->handler = func;
	cb->data = data;

	cb->next = app_status_cb;
	app_status_cb = cb;

	return 0;
}

API int aul_remove_status_local_cb(int (*func)(int status, void *data), void *data)
{
	app_status_cb_info_t *cb = app_status_cb;
	app_status_cb_info_t *tmp = NULL;

	if (app_status_cb
		 && app_status_cb->handler == func
		 && app_status_cb->data == data) {
		cb = app_status_cb->next;
		free(app_status_cb);
		app_status_cb = cb;
		return 0;
	}

	while (cb) {
		if (cb->next
			 && cb->next->handler == func
			 && cb->next->data == data) {
			tmp = cb->next->next;
			free(cb->next);
			cb->next = tmp;
			return 0;
		}

		cb = cb->next;
	}

	return -1;
}

API int aul_invoke_status_local_cb(int status)
{
	app_status_cb_info_t *cb = app_status_cb;

	while (cb) {
		if (cb->handler) {
			if (cb->handler(status, cb->data) < 0)
				aul_remove_status_local_cb(cb->handler, cb->data);
		}

		cb = cb->next;
	}

	return 0;
}

API int aul_running_list_update(char *appid, char *app_path, char *pid)
{
	int ret;
	bundle *kb;

	kb = bundle_create();

	bundle_add(kb, AUL_K_APPID, appid);
	bundle_add(kb, AUL_K_EXEC, app_path);
	bundle_add(kb, AUL_K_PID, pid);

	ret = app_send_cmd(AUL_UTIL_PID, APP_RUNNING_LIST_UPDATE, kb);

	if (kb != NULL)
			bundle_free(kb);

	return ret;
}

