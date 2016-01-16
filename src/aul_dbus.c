/*
 * Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <stdio.h>
#include <stdbool.h>
#include <gio/gio.h>
#include <glib.h>

#include "aul_dbus.h"
#include "aul_api.h"
#include "aul_util.h"
#include "aul.h"

static guint app_dead_id;
static int (*app_dead_handler)(int pid, void *data);
static void *app_dead_data;

static guint app_launch_id;
static int (*app_launch_handler)(int pid, void *data);
static void *app_launch_data;

static guint app_launch_id2;
static int (*app_launch_handler2)(int pid, const char *app_id, void *data);
static void *app_launch_data2;

static guint booting_done_id;
static int (*booting_done_handler) (int pid, void *data);
static void *booting_done_data;

static guint status_id;
static int (*status_handler) (int pid, int status, void *data);
static void *status_data;

static guint cooldown_id;
static int (*cooldown_handler) (const char *cooldown_status, void *data);
static void *cooldown_data;

static GDBusConnection *system_conn = NULL;
static GDBusConnection *session_conn = NULL;

static void __session_dbus_signal_handler(GDBusConnection *connection,
					const gchar *sender_name,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *signal_name,
					GVariant *parameters,
					gpointer user_data)
{
	guint pid;
	gchar *appid;

	if (g_strcmp0(signal_name, AUL_DBUS_APPDEAD_SIGNAL) == 0) {
		g_variant_get(parameters, "(u)", &pid);

		if (app_dead_handler)
			app_dead_handler((int)pid, app_dead_data);
	} else if (g_strcmp0(signal_name, AUL_DBUS_APPLAUNCH_SIGNAL) == 0) {
		g_variant_get(parameters, "(us)", &pid, &appid);

		if (app_launch_handler)
			app_launch_handler((int)pid, app_launch_data);

		if (app_launch_handler2)
			app_launch_handler2((int)pid,
					(const char *)appid, app_launch_data2);

		g_free(appid);
	}
}

static guint __session_dbus_register_signal(const char *object_path,
					const char *interface_name,
					const char *signal_name)
{
	guint s_id;
	GError *err = NULL;
	GDBusConnection *conn = NULL;

	if (session_conn == NULL) {
		conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &err);
		if (conn == NULL) {
			_E("g_bus_get_sync() is failed. %s", err->message);
			g_clear_error(&err);
			return 0;
		}
		session_conn = conn;
	}

	s_id = g_dbus_connection_signal_subscribe(session_conn,
					NULL,
					interface_name,
					signal_name,
					object_path,
					NULL,
					G_DBUS_SIGNAL_FLAGS_NONE,
					__session_dbus_signal_handler,
					NULL,
					NULL);
	if (s_id == 0) {
		_E("g_dbus_connection_signal_subscribe() is failed.");
		if (conn) {
			g_object_unref(conn);
			session_conn = NULL;
		}
	}

	g_clear_error(&err);

	return s_id;
}

static guint __session_dbus_unregister_signal(guint s_id)
{
	if (session_conn == NULL)
		return s_id;

	g_dbus_connection_signal_unsubscribe(session_conn, s_id);

	if (app_dead_handler == NULL
			&& app_launch_handler == NULL
			&& app_launch_handler2 == NULL) {
		g_object_unref(session_conn);
		session_conn = NULL;
	}

	return 0;
}

static void __system_dbus_signal_handler(GDBusConnection *connection,
					const gchar *sender_name,
					const gchar *object_path,
					const gchar *interface_name,
					const gchar *signal_name,
					GVariant *parameters,
					gpointer user_data)
{
	gchar *cooldown_status;
	gint pid = -1;
	gint status;

	if (g_strcmp0(signal_name, SYSTEM_SIGNAL_BOOTING_DONE) == 0) {
		if (booting_done_handler)
			booting_done_handler((int)pid, booting_done_data);
	} else if (g_strcmp0(signal_name,
					RESOURCED_SIGNAL_PROCESS_STATUS) == 0) {
		g_variant_get(parameters, "(ii)", &status, &pid);

		if (status_handler)
			status_handler((int)pid, (int)status, status_data);
	} else if (g_strcmp0(signal_name,
					SYSTEM_SIGNAL_COOLDOWN_CHANGED) == 0) {
		g_variant_get(parameters, "(s)", &cooldown_status);

		if (cooldown_handler)
			cooldown_handler((const char *)cooldown_status,
					cooldown_data);

		g_free(cooldown_status);
	}
}

static guint __system_dbus_register_signal(const char *object_path,
					const char *interface_name,
					const char *signal_name)
{
	guint s_id;
	GError *err = NULL;
	GDBusConnection *conn = NULL;

	if (system_conn == NULL) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (conn == NULL) {
			_E("g_bus_get_sync() is failed. %s", err->message);
			g_clear_error(&err);
			return 0;
		}
		system_conn = conn;
	}

	s_id = g_dbus_connection_signal_subscribe(system_conn,
					NULL,
					interface_name,
					signal_name,
					object_path,
					NULL,
					G_DBUS_SIGNAL_FLAGS_NONE,
					__system_dbus_signal_handler,
					NULL,
					NULL);
	if (s_id == 0) {
		_E("g_dbus_connection_signal_subscribe() is failed.");
		if (conn) {
			g_object_unref(conn);
			system_conn = NULL;
		}
	}

	g_clear_error(&err);

	return s_id;
}

static guint __system_dbus_unregister_signal(guint s_id)
{
	if (system_conn == NULL)
		return s_id;

	g_dbus_connection_signal_unsubscribe(system_conn, s_id);

	if (booting_done_handler == NULL
			&& status_handler == NULL
			&& cooldown_handler == NULL) {
		g_object_unref(system_conn);
		system_conn = NULL;
	}

	return 0;
}

API int aul_listen_app_dead_signal(int (*func)(int, void *), void *data)
{
	app_dead_handler = func;
	app_dead_data = data;

	if (app_dead_handler && app_dead_id == 0) {
		app_dead_id = __session_dbus_register_signal(AUL_DBUS_PATH,
					AUL_DBUS_SIGNAL_INTERFACE,
					AUL_DBUS_APPDEAD_SIGNAL);
		if (app_dead_id == 0)
			return AUL_R_ERROR;
	} else if (app_dead_handler == NULL && app_dead_id) {
		app_dead_id = __session_dbus_unregister_signal(app_dead_id);
		if (app_dead_id)
			return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_listen_app_launch_signal(int (*func)(int, void *), void *data)
{
	app_launch_handler = func;
	app_launch_data = data;

	if (app_launch_handler && app_launch_id == 0) {
		app_launch_id = __session_dbus_register_signal(AUL_DBUS_PATH,
					AUL_DBUS_SIGNAL_INTERFACE,
					AUL_DBUS_APPLAUNCH_SIGNAL);
		if (app_launch_id == 0)
			return AUL_R_ERROR;
	} else if (app_launch_handler == NULL && app_launch_id) {
		app_launch_id = __session_dbus_unregister_signal(app_launch_id);
		if (app_launch_id)
			return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_listen_app_launch_signal_v2(int (*func)(int, const char *, void *),
		void *data)
{
	app_launch_handler2 = func;
	app_launch_data2 = data;

	if (app_launch_handler2 && app_launch_id2 == 0) {
		app_launch_id2 = __session_dbus_register_signal(AUL_DBUS_PATH,
					AUL_DBUS_SIGNAL_INTERFACE,
					AUL_DBUS_APPLAUNCH_SIGNAL);
		if (app_launch_id2 == 0)
			return AUL_R_ERROR;
	} else if (app_launch_handler == NULL && app_launch_id2) {
		app_launch_id2 = __session_dbus_unregister_signal(
				app_launch_id2);
		if (app_launch_id2)
			return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_listen_booting_done_signal(int (*func)(int, void *), void *data)
{
	booting_done_handler = func;
	booting_done_data = data;

	if (booting_done_handler && booting_done_id == 0) {
		booting_done_id = __system_dbus_register_signal(
					SYSTEM_PATH_CORE,
					SYSTEM_INTERFACE_CORE,
					SYSTEM_SIGNAL_BOOTING_DONE);
		if (booting_done_id == 0)
			return AUL_R_ERROR;
	} else if (booting_done_handler == NULL && booting_done_id) {
		booting_done_id = __system_dbus_unregister_signal(
				booting_done_id);
		if (booting_done_id)
			return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_listen_cooldown_signal(int (*func)(const char *, void *),
					void *data)
{
	cooldown_handler = func;
	cooldown_data = data;

	if (cooldown_handler && cooldown_id == 0) {
		cooldown_id = __system_dbus_register_signal(
					SYSTEM_PATH_SYSNOTI,
					SYSTEM_INTERFACE_SYSNOTI,
					SYSTEM_SIGNAL_COOLDOWN_CHANGED);
		if (cooldown_id == 0)
			return AUL_R_ERROR;
	} else if (cooldown_handler == NULL && cooldown_id) {
		cooldown_id = __system_dbus_unregister_signal(cooldown_id);
		if (cooldown_id)
			return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

API int aul_listen_app_status_signal(int (*func)(int, int, void *),
					void *data)
{
	status_handler = func;
	status_data = data;

	if (status_handler && status_id == 0) {
		status_id = __system_dbus_register_signal(
					RESOURCED_PATH_CORE,
					RESOURCED_INTERFACE_CORE,
					RESOURCED_SIGNAL_PROCESS_STATUS);
		if (status_id == 0)
			return AUL_R_ERROR;
	} else if (status_handler == NULL && status_id) {
		status_id = __system_dbus_unregister_signal(status_id);
		if (status_id == 0)
			return AUL_R_ERROR;
	}

	return AUL_R_OK;
}

static int __system_dbus_send_signal(const char *object_path,
					const char *interface_name,
					const char *signal_name,
					GVariant *parameters)
{
	GError *err = NULL;
	GDBusConnection *conn;
	int ret = AUL_R_OK;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	if (conn == NULL) {
		_E("g_bus_get_sync() is failed. %s", err->message);
		g_clear_error(&err);
		return AUL_R_ERROR;
	}

	if (g_dbus_connection_emit_signal(conn,
					NULL,
					object_path,
					interface_name,
					signal_name,
					parameters,
					&err) == FALSE) {
		_E("g_dbus_connection_emit_signal() is failed. %s",
				err->message);
		ret = AUL_R_ERROR;
		goto end;
	}

	if (g_dbus_connection_flush_sync(conn, NULL, &err) == FALSE) {
		_E("g_dbus_connection_flush_sync() is failed. %s",
				err->message);
		ret = AUL_R_ERROR;
	}

end:
	if (conn)
		g_object_unref(conn);

	g_clear_error(&err);

	return ret;
}

API int aul_status_freezer_status(int pid, const char *type)
{
	int ret;
	GVariant *param;

	param = g_variant_new("(si)", type, pid);
	ret = __system_dbus_send_signal(RESOURCED_PROC_OBJECT,
					RESOURCED_PROC_INTERFACE,
					RESOURCED_PROC_METHOD,
					param);
	if (ret != AUL_R_OK) {
		if (g_variant_is_floating(param) == TRUE)
			g_variant_unref(param);
	}

	return ret;
}

API int aul_send_app_launch_request_signal(int pid,
					const char *appid,
					const char *pkgid,
					const char *type)
{
	int ret;
	GVariant *param;
	gboolean ref;

	param = g_variant_new("(isss)", pid, appid, pkgid, type);
	ret = __system_dbus_send_signal(AUL_APP_STATUS_DBUS_PATH,
					AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
					AUL_APP_STATUS_DBUS_LAUNCH_REQUEST,
					param);
	if (param != AUL_R_OK) {
		if (g_variant_is_floating(param) == TRUE)
			g_variant_unref(param);
	}

	return ret;
}

API int aul_send_app_resume_request_signal(int pid,
					const char *appid,
					const char *pkgid,
					const char *type)
{
	int ret;
	const char *empty = "";
	GVariant *param;

	if (appid)
		param = g_variant_new("(isss)", pid, appid, pkgid, type);
	else
		param = g_variant_new("(isss)", pid, empty, empty, empty);

	ret = __system_dbus_send_signal(AUL_APP_STATUS_DBUS_PATH,
					AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
					AUL_APP_STATUS_DBUS_RESUME_REQUEST,
					param);
	if (ret != AUL_R_OK) {
		if (g_variant_is_floating(param) == TRUE)
			g_variant_unref(param);
	}

	return ret;
}

API int aul_send_app_terminate_request_signal(int pid,
					const char *appid,
					const char *pkgid,
					const char *type)
{
	int ret;
	const char *empty = "";
	GVariant *param;

	if (appid)
		param = g_variant_new("(isss)", pid, appid, pkgid, type);
	else
		param = g_variant_new("(isss)", pid, empty, empty, empty);

	ret = __system_dbus_send_signal(AUL_APP_STATUS_DBUS_PATH,
					AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
					AUL_APP_STATUS_DBUS_TERMINATE_REQUEST,
					param);
	if (ret != AUL_R_OK) {
		if (g_variant_is_floating(param) == TRUE)
			g_variant_unref(param);
	}

	return ret;
}

API int aul_send_app_status_change_signal(int pid,
					const char *appid,
					const char *pkgid,
					const char *status,
					const char *type)
{
	int ret;
	const char *empty = "";
	GVariant *param;

	if (appid)
		param = g_variant_new("(issss)",
				pid, appid, pkgid, status, type);
	else
		param = g_variant_new("(issss)",
				pid, empty, empty, status, type);

	ret = __system_dbus_send_signal(AUL_APP_STATUS_DBUS_PATH,
					AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
					AUL_APP_STATUS_DBUS_STATUS_CHANGE,
					param);
	if (ret != AUL_R_OK) {
		if (g_variant_is_floating(param) == TRUE)
			g_variant_unref(param);
	}

	return ret;
}

API int aul_send_app_terminated_signal(int pid)
{
	int ret;
	GVariant *param;

	param = g_variant_new("(i)", pid);
	ret = __system_dbus_send_signal(AUL_APP_STATUS_DBUS_PATH,
					AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
					AUL_APP_STATUS_DBUS_TERMINATED,
					param);
	if (ret != AUL_R_OK) {
		if (g_variant_is_floating(param) == TRUE)
			g_variant_unref(param);
	}

	return ret;
}

API int aul_send_app_group_signal(int owner_pid,
		int child_pid,
		const char *child_pkgid)
{
	int ret;
	const char *empty = "";
	GVariant *param;

	if (child_pkgid)
		param = g_variant_new("(iis)",
					owner_pid, child_pid, child_pkgid);
	else
		param = g_variant_new("(iis)",
					owner_pid, child_pid, empty);

	ret = __system_dbus_send_signal(AUL_APP_STATUS_DBUS_PATH,
					AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
					AUL_APP_STATUS_DBUS_GROUP,
					param);
	if (ret != AUL_R_OK) {
		if (g_variant_is_floating(param) == TRUE)
			g_variant_unref(param);
	}

	return ret;
}

API int aul_is_tep_mount_dbus_done(const char *tep_string)
{
	GError *err = NULL;
	GDBusConnection *conn;
	GDBusMessage *msg = NULL;
	GDBusMessage *reply = NULL;
	GVariant *body;
	int ret = AUL_R_ERROR;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
	if (conn == NULL) {
		_E("g_bus_get_sync() is failed. %s", err->message);
		g_clear_error(&err);
		return AUL_R_ERROR;
	}

	msg = g_dbus_message_new_method_call(TEP_BUS_NAME,
					TEP_OBJECT_PATH,
					TEP_INTERFACE_NAME,
					TEP_IS_MOUNTED_METHOD);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed. %s",
					err->message);
		goto end;
	}
	g_dbus_message_set_body(msg, g_variant_new("(s)", tep_string));

	reply = g_dbus_connection_send_message_with_reply_sync(conn,
					msg,
					G_DBUS_SEND_MESSAGE_FLAGS_NONE,
					500,
					NULL,
					NULL,
					&err);
	if (reply == NULL) {
		_E("g_dbus_connection_send_message_with_reply_sync() "
					"is failed. %s", err->message);
		goto end;
	}

	body = g_dbus_message_get_body(reply);
	if (body == NULL) {
		_E("g_dbus_message_get_body() is failed.");
		goto end;
	}

	ret = (int)g_variant_get_int32(body);

end:
	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);
	if (conn)
		g_object_unref(conn);

	g_clear_error(&err);

	return ret;
}
