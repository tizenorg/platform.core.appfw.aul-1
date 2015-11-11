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
#include <stdlib.h>

#include <aul.h>
#include <bundle.h>

#include "simple_util.h"
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

static int (*_aul_widget_handler) (const char *widget_id, const char *instance_id, int status, bundle *extra, void *data) = NULL;
static void *_aul_widget_data;

SLPAPI int aul_status_update(int status)
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

SLPAPI  int aul_app_get_status_bypid(int pid)
{
	int ret;

	if (pid == getpid()) {
		return app_status;
	}

	ret = __app_send_raw(AUL_UTIL_PID, APP_GET_STATUS, (unsigned char *)&pid, sizeof(pid));

	return ret;
}

SLPAPI int aul_add_status_local_cb(int (*func)(int status, void *data), void *data)
{
	app_status_cb_info_t *cb = app_status_cb;

	if (func == NULL)
		return -1;

	// check known callback
	while (cb) {
		if (cb && cb->handler == func && cb->data == data) {
			// already in list
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

SLPAPI int aul_remove_status_local_cb(int (*func)(int status, void *data), void *data)
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

SLPAPI int aul_invoke_status_local_cb(int status)
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

SLPAPI int aul_running_list_update(char *appid, char *app_path, char *pid)
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

int app_widget_update(bundle *b)
{
	const char *widget_id;
	const char *instance_id;
	const char *status_str;
	int status = 0;

	if (b == NULL) {
		_E("invalid arguments");
		return -1;
	}

	widget_id = bundle_get_val(b, AUL_K_APPID);
	instance_id = bundle_get_val(b, AUL_K_WIDGET_INSTANCE_ID);
	status_str = bundle_get_val(b, AUL_K_WIDGET_INSTANCE_STATUS);
	if (status_str)
		status = atoi(status_str);

	_D("widget_id: %s instnace_id: %s status: %d", widget_id, instance_id, status);

	if (_aul_widget_handler) {
		_aul_widget_handler(widget_id, instance_id, status, b, _aul_widget_data);
	}

	return 0;
}

SLPAPI int aul_listen_widget_status(int (*aul_handler)(const char *widget_id, const char *instance_id, int status, bundle *extra, void *data), void *user_data)
{
	int pid = getpid();
	int ret = 0;

	_aul_widget_handler = aul_handler;
	_aul_widget_data = user_data;

	ret = __app_send_raw(AUL_UTIL_PID, APP_LISTEN_WIDGET, (unsigned char *)&pid, sizeof(pid));

	return ret;
}

SLPAPI int aul_update_widget_status(const char *widget_id, const char *instance_id, int status, bundle *data, int receiver_pid)
{
	bundle *b = NULL;
	char status_buf[6];
	char pid_buf[6];
	int ret = 0;

	if (!widget_id || !instance_id)
		return AUL_R_EINVAL;

	if (data)
		b = bundle_dup(data);
	else
		b = bundle_create();

	if (!b) {
		_E("out of memory");
		return -1;
	}

	bundle_add(b, AUL_K_APPID, widget_id);
	bundle_add(b, AUL_K_WIDGET_INSTANCE_ID, instance_id);
	sprintf(status_buf, "%d", status);
	bundle_add(b, AUL_K_WIDGET_INSTANCE_STATUS, status_buf);
	if (receiver_pid) {
		sprintf(pid_buf, "%d", receiver_pid);
		bundle_add(b, AUL_K_WIDGET_INTERNAL_STATUS, pid_buf);
	}

	ret = app_send_cmd_with_noreply(AUL_UTIL_PID, APP_WIDGET_UPDATE, b);

	bundle_free(b);

	return ret;
}

