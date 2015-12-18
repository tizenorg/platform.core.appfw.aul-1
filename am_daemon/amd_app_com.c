/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <glib.h>
#include <bundle.h>
#include "aul.h"
#include "launch.h"
#include "simple_util.h"
#include "amd_cynara.h"
#include "app_sock.h"
#include "aul_app_com.h"
#include "amd_app_com.h"

struct endpoint_info {
	char *endpoint;
	unsigned int propagate;
	char *privilege;
	GList *clients;
};

struct client_info {
	int pid;
	char *filter;
	struct endpoint_info *endpoint;
};

static GHashTable *cpid_tbl = NULL;
static GHashTable *endpoint_tbl = NULL;

static void __remove_client(struct endpoint_info *info, int cpid);

static void __free_endpoint(struct endpoint_info *info)
{
	if (!info)
		return;

	if (info->endpoint) {
		g_free(info->endpoint);
		info->endpoint = NULL;
	}

	if (info->privilege) {
		g_free(info->privilege);
		info->privilege = NULL;
	}

	if (info->clients) {
		g_list_free(info->clients);
		info->clients = NULL;
	}

	g_free(info);
}

int app_com_broker_init()
{
	if (!endpoint_tbl) {
		endpoint_tbl = g_hash_table_new(g_str_hash, g_str_equal);
		if (endpoint_tbl == NULL) {
			_E("out of memory");
			return -1;
		}
	}

	if (!cpid_tbl) {
		cpid_tbl = g_hash_table_new(g_direct_hash, g_direct_equal);
		if (cpid_tbl == NULL) {
			_E("out of memory");
			return -1;
		}
	}

	return 0;
}

static void __remove_cpid(gpointer key, gpointer value, gpointer user_data)
{
	int pid = GPOINTER_TO_INT(key);
	struct endpoint_info *info = NULL;
	GList *client_list = (GList *)value;
	while (client_list) {
		info = (struct endpoint_info *)client_list->data;
		__remove_client(info, pid);
		client_list = client_list->next;
	}
	g_list_free((GList *)value);
}

int app_com_broker_fini()
{
	if (cpid_tbl) {
		g_hash_table_foreach(cpid_tbl, __remove_cpid, NULL);
		g_hash_table_destroy(cpid_tbl);
		cpid_tbl = NULL;
	}

	if (endpoint_tbl) {
		g_hash_table_destroy(endpoint_tbl);
		endpoint_tbl = NULL;
	}

	return 0;
}

int app_com_add_endpoint(const char *endpoint, unsigned int propagate, const char *assoc_priv)
{
	struct endpoint_info *info = NULL;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (info) {
		_E("endpoint already exists.");
		return AUL_APP_COM_R_ERROR_ENDPOINT_ALREADY_EXISTS;
	}

	_E("endpoint=%s propagate=%d assoc_priv=%s", endpoint, propagate, assoc_priv);
	info = (struct endpoint_info *)g_malloc0(sizeof(struct endpoint_info));
	if (info == NULL) {
		_E("out of memory");
		return AUL_APP_COM_R_ERROR_FATAL_ERROR;
	}

	info->endpoint = g_strdup(endpoint);
	info->propagate = propagate;
	info->clients = NULL;
	if (assoc_priv)
		info->privilege = g_strdup(assoc_priv);
	else
		info->privilege = NULL;

	g_hash_table_insert(endpoint_tbl, info->endpoint, info);

	return AUL_APP_COM_R_ERROR_OK;
}

int app_com_remove_endpoint(const char *endpoint)
{
	struct endpoint_info *info = NULL;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (!info) {
		_D("endpoint not exists");
		return AUL_APP_COM_R_ERROR_UNKNOWN_ENDPOINT;
	}

	if (info->clients != NULL) {
		_D("client active");
		return AUL_APP_COM_R_ERROR_CLIENT_REMAINING;
	}

	g_hash_table_remove(endpoint_tbl, endpoint);
	__free_endpoint(info);

	return AUL_APP_COM_R_ERROR_OK;
}

static void __add_client(struct endpoint_info *info, const char *filter, int pid)
{
	GList *client_list = NULL;
	struct client_info *c = NULL;

	c = (struct client_info *)g_malloc0(sizeof(struct client_info));
	if (c == NULL) {
		_E("out of memory");
		return AUL_APP_COM_R_ERROR_FATAL_ERROR;
	}

	c->endpoint = info;
	c->pid = pid;
	if (filter)
		c->filter = g_strdup(filter);
	else
		c->filter = NULL;

	info->clients = g_list_append(info->clients, c);
	client_list = g_hash_table_lookup(cpid_tbl, GINT_TO_POINTER(pid));
	if (client_list == NULL) {
		client_list = g_list_append(client_list, info);
		g_hash_table_insert(cpid_tbl, GINT_TO_POINTER(pid), client_list);
	} else {
		client_list = g_list_append(client_list, info);
	}

}

int app_com_join(const char *endpoint, int cpid, int clifd, const char *filter)
{
	struct endpoint_info *info = NULL;
	int ret = 0;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (!info) {
		_E("endpoint not exists: %s", endpoint);
		return AUL_APP_COM_R_ERROR_UNKNOWN_ENDPOINT;
	}

	_E("endpoint=%s cpid=%d clifd=%d filter=%s", endpoint, cpid, clifd, filter);

	if (info->privilege) {
		ret = check_privilege_by_cynara(clifd, info->privilege);
		if (ret < 0) {
			_E("insufficient privilege: %s", info->privilege);
			return AUL_APP_COM_R_ERROR_ILLEGAL_ACCESS;
		}
	}

	__add_client(info, filter, cpid);

	return AUL_APP_COM_R_ERROR_OK;
}

static int __check_filter(const char *filter, int cpid, int rpid, bundle *b)
{
	/* TODO */
	return 0;
}

int app_com_send(const char *endpoint, int cpid, bundle *envelope)
{
	struct endpoint_info *info = NULL;
	GList *client_head = NULL;
	struct client_info *client = NULL;
	int ret = 0;
	int result = 0;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (!info) {
		_E("endpoint not exsits: %s", endpoint);
		return AUL_APP_COM_R_ERROR_UNKNOWN_ENDPOINT;
	}

	/* TODO delete internal keys */

	_D("endpoint=%s cpid=%d", endpoint, cpid);

	bundle_add_str(envelope, AUL_K_COM_ENDPOINT, endpoint);
	result = AUL_APP_COM_R_OK;
	bundle_add_byte(envelope, AUL_K_COM_RESULT, &result, sizeof(result));

	client_head = info->clients;
	while (client_head) {
		client = (struct client_info *)client_head->data;
		client_head = client_head->next;
		if (client == NULL)
			continue;

		if (client->pid == cpid)
			continue;

		if (client->filter && __check_filter(client->filter, cpid, client->pid, envelope) < 0) {
			continue;
		}

		ret = app_send_cmd_with_noreply(client->pid, APP_COM_MESSAGE, envelope);
		if (ret < 0)
			_E("failed to send message pid: %d (%d)", client->pid, ret);

	}

	return AUL_APP_COM_R_ERROR_OK;
}

static void __remove_client(struct endpoint_info *info, int cpid)
{
	GList *client_head = NULL;
	struct client_info *client = NULL;

	client_head = info->clients;
	while (client_head) {
		client = (struct client_info *)client_head->data;
		if (client && client->pid == cpid) {
			info->clients = g_list_remove_link(info->clients, client_head);
			if (client->filter)
				g_free(client->filter);

			g_free(client);
		}

		client_head = client_head->next;
	}

	if (info->clients == NULL) {
		g_hash_table_remove(endpoint_tbl, info->endpoint);
		_D("endpoint removed: %s", info->endpoint);
		__free_endpoint(info);
	}
}

int app_com_leave(const char *endpoint, int cpid)
{
	struct endpoint_info *info = NULL;

	info = g_hash_table_lookup(endpoint_tbl, endpoint);
	if (!info) {
		_E("endpoint not exists: %s", endpoint);
		return AUL_APP_COM_R_ERROR_UNKNOWN_ENDPOINT;
	}

	__remove_client(info, cpid);

	return AUL_APP_COM_R_ERROR_OK;
}

int app_com_client_remove(int cpid)
{
	GList *client_list = NULL;
	struct endpoint_info *info = NULL;

	client_list = g_hash_table_lookup(cpid_tbl, GINT_TO_POINTER(cpid));
	if (client_list == NULL)
		return AUL_APP_COM_R_ERROR_FATAL_ERROR;

	while (client_list) {
		info = (struct endpoint_info *)client_list->data;
		if (info)
			__remove_client(info, cpid);

		client_list = client_list->next;
	}

	g_hash_table_remove(cpid_tbl, GINT_TO_POINTER(cpid));

	return AUL_APP_COM_R_ERROR_OK;
}


