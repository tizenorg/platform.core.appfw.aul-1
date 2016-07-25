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
#include <glib.h>
#include <bundle.h>
#include "aul.h"
#include "aul_util.h"
#include "aul_sock.h"
#include "aul_cmd.h"
#include "aul_error.h"
#include "launch.h"

static const char *__to_appid(const char *widget_id)
{
	const char *appid;
	appid = g_strstr_len(widget_id, strlen(widget_id), "@") + 1;
	if (appid != (const char *)1) {
		if (appid > widget_id + (sizeof(char) * strlen(widget_id)))
			appid = (char *)widget_id;
	} else {
		appid = (char *)widget_id;
	}

	return appid;
}

API int aul_widget_instance_add(const char *widget_id, const char *instance_id)
{
	int ret;
	bundle *kb;

	if (widget_id == NULL || instance_id == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);
	bundle_add_str(kb, AUL_K_WIDGET_INSTANCE_ID, instance_id);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), WIDGET_ADD, kb,
		AUL_SOCK_NONE);

	bundle_free(kb);
	if (ret < 0)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

API int aul_widget_instance_del(const char *widget_id, const char *instance_id)
{
	int ret;
	bundle *kb;

	if (widget_id == NULL || instance_id == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);
	bundle_add_str(kb, AUL_K_WIDGET_INSTANCE_ID, instance_id);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), WIDGET_DEL, kb,
		AUL_SOCK_NONE);

	bundle_free(kb);
	if (ret < 0)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

struct __cb_data {
	aul_widget_instance_foreach_cb cb;
	void *data;
};

static void __foreach_cb(const char *key, const int type,
		const bundle_keyval_t *kv, void *user_data)
{
	struct __cb_data *cb_data = (struct __cb_data *)user_data;

	cb_data->cb(key, cb_data->data);
}

API int aul_widget_instance_foreach(const char *widget_id,
		aul_widget_instance_foreach_cb cb, void *data)
{
	int ret;
	int fd;
	bundle *kb;
	app_pkt_t *pkt = NULL;
	bundle *list_kb = NULL;
	struct __cb_data cb_data;

	if (widget_id == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_APPID, __to_appid(widget_id));
	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);

	fd = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), WIDGET_LIST, kb,
		AUL_SOCK_ASYNC);

	if (fd > 0) {
		ret = aul_sock_recv_reply_pkt(fd, &pkt);
		if (ret < 0 || pkt == NULL) {
			_E("failed to get instance list of %s", widget_id);
		} else {
			list_kb = bundle_decode(pkt->data, pkt->len);
			if (list_kb) {
				cb_data.cb = cb;
				cb_data.data = data;
				bundle_foreach(list_kb, __foreach_cb, &cb_data);
			}
		}
	} else {
		ret = fd;
	}

	if (pkt)
		free(pkt);

	bundle_free(kb);

	if (ret < 0)
		return aul_error_convert(ret);

	return AUL_R_OK;
}

API int aul_widget_instance_update(const char *widget_id,
		const char *instance_id, bundle *param)
{
	int ret;
	bundle *kb = param;
	const char *appid;

	if (widget_id == NULL)
		return AUL_R_EINVAL;

	if (kb == NULL)
		kb = bundle_create();

	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	appid = __to_appid(widget_id);

	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);

	if (instance_id)
		bundle_add_str(kb, AUL_K_WIDGET_INSTANCE_ID, instance_id);

	ret = app_request_to_launchpad_for_uid(WIDGET_UPDATE, appid, kb,
			getuid());

	if (param == NULL)
		bundle_free(kb);

	return ret;
}

API int aul_widget_instance_get_content(const char *widget_id,
		const char *instance_id, char **content)
{
	int ret;
	bundle *kb;
	int fd[1] = {0};
	app_pkt_t *pkt = NULL;

	if (widget_id == NULL || instance_id == NULL)
		return AUL_R_EINVAL;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return AUL_R_ERROR;
	}

	bundle_add_str(kb, AUL_K_WIDGET_ID, widget_id);
	bundle_add_str(kb, AUL_K_WIDGET_INSTANCE_ID, instance_id);

	ret = aul_sock_send_bundle(AUL_UTIL_PID, getuid(), WIDGET_GET_CONTENT,
		kb, AUL_SOCK_ASYNC);

	if (ret > 0) {
		ret = aul_sock_recv_reply_sock_fd(ret, fd, 1);
		if (ret == 0 && fd[0]) {
			ret = aul_sock_recv_reply_pkt(fd[0], &pkt);
			if (ret == 0 && pkt && pkt->cmd == 0) {
				*content = strdup((const char *)pkt->data);
				_D("recieved content: %s", *content);
			} else {
				if (pkt)
					ret = pkt->cmd;

				_E("failed to get content");
			}
		} else {
			_E("failed to get socket fd:%d", ret);
		}
	}

	bundle_free(kb);

	if (ret < 0)
		ret = aul_error_convert(ret);

	return ret;
}

