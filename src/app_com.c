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
 *
 */

#define _GNU_SOURCE
#include <glib.h>
#include "aul.h"
#include "launch.h"
#include "simple_util.h"
#include "aul_util.h"
#include "aul_api.h"
#include "app_sock.h"
#include "app_com.h"

static GList *handlers = NULL;

struct app_com_handler {
	char *endpoint;
	app_com_receiver handler;
	void *user_data;	
};

int app_com_recv(bundle *b)
{
	int ret = 0;
	char *endpoint = NULL;
	size_t result_sz;
	int result;
	GList *head = handlers;
	struct app_com_handler *handler = NULL;

	if (b == NULL)
		return -1;

	ret = bundle_get_str(b, AUL_K_COM_ENDPOINT, &endpoint);
	if (ret != BUNDLE_ERROR_NONE)
		return -1;

	ret = bundle_get_byte(b, AUL_K_COM_RESULT, (void **)&result, &result_sz);
	if (ret != BUNDLE_ERROR_NONE)
		return -1;

	while (head) {
		handler = (struct app_com_handler *)head->data;
		if (handler && handler->endpoint && g_strcmp0(handler->endpoint, endpoint) == 0)
			handler->handler(endpoint, result, b, handler->user_data);

		head = head->next;
	}

	return 0;
}

SLPAPI int aul_app_com_permission_set_propagation(aul_app_com_permission_t *permission, aul_app_com_propagate_option_e option)
{
	if (permission)
		permission->propagation = option;

	return 0;
}

SLPAPI int aul_app_com_permission_set_privilege(aul_app_com_permission_t *permission, const char *privilege)
{
	if (permission) {
		if (permission->privilege)
			g_free(permission->privilege);

		permission->privilege = g_strdup(privilege);
	}

	return 0;
}

static void __add_handler(const char *endpoint, app_com_receiver handler, void *user_data)
{
	struct app_com_handler *h = NULL;
	h = (struct app_com_handler *)g_malloc(sizeof(struct app_com_handler));
	if (h == NULL) {
		_E("out of memory");
		return; 
	}

	h->handler = handler;
	h->user_data = user_data;
	h->endpoint = g_strdup(endpoint);

	handlers = g_list_append(handlers, h);
}

SLPAPI int aul_app_com_create(const char *endpoint, aul_app_com_permission_t *permission, app_com_receiver handler, void *user_data)
{
	bundle *b = NULL;
	int ret = 0;
	
	if (endpoint == NULL)
		return -1;

	b = bundle_create();

	if (!b) {
		_E("out of memory");
		return -1;
	}

	bundle_add_str(b, AUL_K_COM_ENDPOINT, endpoint);

	if (permission) {
		if (permission->propagation)
			bundle_add_byte(b, AUL_K_COM_PROPAGATE,
				(void *)(GUINT_TO_POINTER(permission->propagation)), sizeof(unsigned int));

		if (permission->privilege)
			bundle_add_str(b, AUL_K_COM_PRIVILEGE, permission->privilege);
	}

	ret = app_send_cmd(AUL_UTIL_PID, APP_COM_CREATE, b);
	bundle_free(b);

	if (ret == 0)
		__add_handler(endpoint, handler, user_data);

	return ret;
}

SLPAPI int aul_app_com_join(const char *endpoint, const char *filter, app_com_receiver handler, void *user_data)
{
	bundle *b = NULL;
	int ret = 0;

	if (endpoint == NULL || handler == NULL)
		return -1;

	b = bundle_create();

	if (!b) {
		_E("out of memory");
		return -1;
	}

	bundle_add_str(b, AUL_K_COM_ENDPOINT, endpoint);
	if (filter)
		bundle_add_str(b, AUL_K_COM_FILTER, filter);

	ret = app_send_cmd(AUL_UTIL_PID, APP_COM_JOIN, b);
	bundle_free(b);

	if (ret == 0)
		__add_handler(endpoint, handler, user_data);

	return ret;
}

SLPAPI int aul_app_com_send(const char *endpoint, bundle *envelope)
{
	int ret = 0;

	if (endpoint == NULL || envelope == NULL)
		return -1;

	bundle_add_str(envelope, AUL_K_COM_ENDPOINT, endpoint);

	ret = app_send_cmd(AUL_UTIL_PID, APP_COM_SEND, envelope);

	return ret;
}

SLPAPI int aul_app_com_leave(const char *endpoint, app_com_receiver handler, void *user_data)
{
	bundle *b = NULL;
	int ret = 0;
	GList *head = handlers;
	struct app_com_handler *h = NULL;
	int endpoint_cnt = 0;

	if (endpoint == NULL || handler == NULL)
		return -1;

	while (head) {
		h = (struct app_com_handler *)head->data;
		if (h && h->endpoint && g_strcmp0(h->endpoint, endpoint) == 0) {
			if (h->handler == handler && h->user_data == user_data) {
				handlers = g_list_remove_link(handlers, head);
				g_free(h->endpoint);
				g_free(h);
			} else {
				endpoint_cnt++;
			}
		}

		head = head->next;
	}

	if (endpoint_cnt > 0)
		return 0;

	b = bundle_create();
	if (!b) {
		_E("out of memory");
		return -1;
	}

	bundle_add_str(b, AUL_K_COM_ENDPOINT, endpoint);

	ret = app_send_cmd(AUL_UTIL_PID, APP_COM_LEAVE, b);

	bundle_free(b);
	return ret;
}
