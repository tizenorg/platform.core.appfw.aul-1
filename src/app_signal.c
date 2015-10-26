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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "app_signal.h"
#include "aul_api.h"
#include "simple_util.h"
#include "aul.h"

static int (*_app_dead_handler) (int pid, void *data);
static void *_app_dead_data;

static int (*_app_launch_handler) (int pid, void *data);
static void *_app_launch_data;

static int (*_booting_done_handler) (int pid, void *data);
static void *_booting_done_data;

static int (*_status_handler) (int pid, int status, void *data);
static void *_status_data;

static int (*_cooldown_handler) (const char *cooldown_status, void *data);
static void *_cooldown_data;

static DBusConnection *system_conn;
static DBusConnection *session_conn;

static DBusConnection *send_conn;

static DBusError err;

static int system_bus_ref;
static int session_bus_initialized;


static DBusHandlerResult
__dbus_signal_filter_system(DBusConnection *conn, DBusMessage *message,
		       void *user_data)
{
	const char *interface;
	const char *cooldown_status;
	int pid = -1;
	int status;

	DBusError error;
	dbus_error_init(&error);

	interface = dbus_message_get_interface(message);
	if (interface == NULL) {
		_E("reject by security issue - no interface\n");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (dbus_message_is_signal(
	  message, interface, SYSTEM_SIGNAL_BOOTING_DONE)) {
		if (_booting_done_handler)
			_booting_done_handler(pid, _booting_done_data);
	} else if (dbus_message_is_signal(
	  message, interface, RESOURCED_SIGNAL_PROCESS_STATUS)) {
		if (dbus_message_get_args(message, &error, DBUS_TYPE_INT32, &status,
			DBUS_TYPE_INT32, &pid, DBUS_TYPE_INVALID) == FALSE) {
			_E("Failed to get data: %s", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		if (_status_handler)
			_status_handler(pid, status, _status_data);
	} else if (dbus_message_is_signal(
	  message, interface, SYSTEM_SIGNAL_COOLDOWN_CHANGED)) {
		if (dbus_message_get_args(message, &error, DBUS_TYPE_STRING, &cooldown_status,
			DBUS_TYPE_INVALID) == FALSE) {
			_E("Failed to get data: %s", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		if (_cooldown_handler)
			_cooldown_handler(cooldown_status, _cooldown_data);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusHandlerResult
__dbus_signal_filter_session(DBusConnection *conn, DBusMessage *message,
		       void *user_data)
{
	const char *interface;
	const char *cooldown_status;
	int pid = -1;
	int status;

	DBusError error;
	dbus_error_init(&error);

	interface = dbus_message_get_interface(message);
	if (interface == NULL) {
		_E("reject by security issue - no interface\n");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (dbus_message_is_signal(
	  message, interface, AUL_DBUS_APPDEAD_SIGNAL)) {
		if (dbus_message_get_args(message, &error, DBUS_TYPE_UINT32,
		     &pid, DBUS_TYPE_INVALID) == FALSE) {
			_E("Failed to get data: %s", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		if (_app_dead_handler)
			_app_dead_handler(pid, _app_dead_data);
	} else if (dbus_message_is_signal(
	  message, interface, AUL_DBUS_APPLAUNCH_SIGNAL)) {
		if (dbus_message_get_args(message, &error, DBUS_TYPE_UINT32,
		     &pid, DBUS_TYPE_INVALID) == FALSE) {
			_E("Failed to get data: %s", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}
		if (_app_launch_handler)
			_app_launch_handler(pid, _app_launch_data);
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static int __app_dbus_signal_handler_init(const char *path,
		const char *interface, bool system_bus)
{
	DBusConnection *bus;
	DBusError error;
	char rule[MAX_LOCAL_BUFSZ];

	if (!system_bus && session_bus_initialized)
		return 0;

	dbus_error_init(&error);
	bus = dbus_bus_get_private(system_bus ? DBUS_BUS_SYSTEM : DBUS_BUS_SESSION, &error);
	if (!bus) {
		_E("Failed to connect to the D-BUS daemon: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}
	dbus_connection_setup_with_g_main(bus, NULL);

	snprintf(rule, MAX_LOCAL_BUFSZ,
		 "path='%s',type='signal',interface='%s'", path, interface);
	/* listening to messages */
	dbus_bus_add_match(bus, rule, &error);
	if (dbus_error_is_set(&error)) {
		_E("Fail to rule set: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}

	if (dbus_connection_add_filter(bus,
				system_bus ? __dbus_signal_filter_system : __dbus_signal_filter_session,
				NULL, NULL) == FALSE) {
		_E("add filter fail");
		return -1;
	}

	if (system_bus) {
		system_conn = bus;
	} else {
		session_conn = bus;
		session_bus_initialized = 1;
	}

	_D("app signal initialized");

	return 0;
}

static int __app_dbus_signal_handler_fini(const char *path, const char *interface, bool system_bus)
{
	DBusConnection *bus;
	DBusError error;
	char rule[MAX_LOCAL_BUFSZ];

	if (system_bus) {
		bus = system_conn;
	} else {
		if (!session_bus_initialized)
			return 0;
		bus = session_conn;
	}

	dbus_error_init(&error);

	dbus_connection_remove_filter(bus,
			system_bus ? __dbus_signal_filter_system : __dbus_signal_filter_session, NULL);

	snprintf(rule, MAX_LOCAL_BUFSZ,
		 "path='%s',type='signal',interface='%s'", path, interface);
	dbus_bus_remove_match(bus, rule, &error);
	if (dbus_error_is_set(&error)) {
		_E("Fail to rule unset: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}

	dbus_connection_close(bus);
	dbus_connection_unref(bus);

	_D("app signal finialized");

	return 0;
}

SLPAPI int aul_listen_app_dead_signal(int (*func) (int, void *), void *data)
{
	if (func) {
		if (__app_dbus_signal_handler_init(AUL_DBUS_PATH, AUL_DBUS_SIGNAL_INTERFACE, false) < 0) {
			_E("error app signal init");
			return AUL_R_ERROR;
		}
	} else if (_app_launch_handler == NULL) {
		if (__app_dbus_signal_handler_fini(AUL_DBUS_PATH, AUL_DBUS_SIGNAL_INTERFACE, false) < 0) {
			_E("error app signal fini");
			return AUL_R_ERROR;
		}
	}
	_app_dead_handler = func;
	_app_dead_data = data;

	return AUL_R_OK;
}

SLPAPI int aul_listen_app_launch_signal(int (*func) (int, void *), void *data)
{
	if (func) {
		if (__app_dbus_signal_handler_init(AUL_DBUS_PATH, AUL_DBUS_SIGNAL_INTERFACE, false) < 0) {
			_E("error app signal init");
			return AUL_R_ERROR;
		}
	} else if (_app_dead_handler == NULL) {
		if (__app_dbus_signal_handler_fini(AUL_DBUS_PATH, AUL_DBUS_SIGNAL_INTERFACE, false) < 0) {
			_E("error app signal fini");
			return AUL_R_ERROR;
		}
	}
	_app_launch_handler = func;
	_app_launch_data = data;

	return AUL_R_OK;
}

SLPAPI int aul_listen_booting_done_signal(int (*func) (int, void *), void *data)
{
	if (func) {
		if (__app_dbus_signal_handler_init(SYSTEM_PATH_CORE, SYSTEM_INTERFACE_CORE, true) < 0) {
			_E("error app signal init");
			return AUL_R_ERROR;
		}
		system_bus_ref++;
	} else {
		system_bus_ref--;
	}

	_booting_done_handler = func;
	_booting_done_data = data;

	if (!system_bus_ref) {
		if (__app_dbus_signal_handler_fini(SYSTEM_PATH_CORE, SYSTEM_INTERFACE_CORE, true) < 0) {
			_E("error app signal fini");
			return AUL_R_ERROR;
		}
	}
	return AUL_R_OK;
}

SLPAPI int aul_listen_cooldown_signal(int (*func) (const char *, void *), void *data)
{
	if (func) {
		if (__app_dbus_signal_handler_init(SYSTEM_PATH_SYSNOTI, SYSTEM_INTERFACE_SYSNOTI, true) < 0) {
			_E("error app signal init");
			return AUL_R_ERROR;
		}
		system_bus_ref++;
	} else {
		system_bus_ref--;
	}
	_cooldown_handler = func;
	_cooldown_data = data;

	if (!system_bus_ref) {
		if (__app_dbus_signal_handler_fini(SYSTEM_PATH_SYSNOTI, SYSTEM_INTERFACE_SYSNOTI, true) < 0) {
			_E("error app signal fini");
			return AUL_R_ERROR;
		}
	}
	return AUL_R_OK;
}

SLPAPI int aul_listen_app_status_signal(int (*func) (int, int, void *), void *data)
{
	if (func) {
		if (__app_dbus_signal_handler_init(RESOURCED_PATH_CORE, RESOURCED_INTERFACE_CORE, true) < 0) {
			_E("error app signal init");
			return AUL_R_ERROR;
		}
		system_bus_ref++;
	} else {
		system_bus_ref--;
	}

	_status_handler = func;
	_status_data = data;

	if (!system_bus_ref) {
		if (__app_dbus_signal_handler_fini(RESOURCED_PATH_CORE, RESOURCED_INTERFACE_CORE, true) < 0) {
			_E("error app signal fini");
			return AUL_R_ERROR;
		}
	}
	return AUL_R_OK;
}

static int __app_dbus_send_init(void)
{
	if (send_conn)
		return 0;

	dbus_error_init(&err);
	send_conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (!send_conn) {
		_E("Fail to dbus_bus_get : %s", err.message);
		return -1;
	}

	return 0;
}

SLPAPI int aul_update_freezer_status(int pid, const char *type)
{
	DBusError err;
	DBusMessage *msg = NULL;
	dbus_uint32_t serial = 0;

	int ret = -1;

	dbus_error_init(&err);

	_W("send_update_freezer_status, pid: %d, type: %s", pid, type);

	if (__app_dbus_send_init() < 0)
		return -1;

	msg = dbus_message_new_signal(RESOURCED_PROC_OBJECT,
			RESOURCED_PROC_INTERFACE,
			RESOURCED_PROC_METHOD);
	if (!msg) {
		_E("Could not create DBus Message.");
		ret = -1;
		goto end;
	}

	if (!dbus_message_append_args(msg,
			DBUS_TYPE_STRING, &type,
			DBUS_TYPE_INT32, &pid,
			DBUS_TYPE_INVALID)) {
		_E("Failed to append a D-Bus Message.");
		ret = -1;
	}

	if (!dbus_connection_send(send_conn, msg, &serial)) {
		_E("Failed to send a D-Bus Message.");
		ret = -1;
	}

	dbus_connection_flush(send_conn);

end:
	dbus_error_free(&err);

	if (msg) {
		dbus_message_unref(msg);
	}

	if (send_conn) {
		dbus_connection_unref(send_conn);
	}

	return ret;

}

SLPAPI int aul_send_app_launch_request_signal(int pid, const char *appid, const char *pkgid, const char *type)
{
	DBusMessage *msg = NULL;
	dbus_uint32_t serial = 0;

	int ret = -1;

	if (__app_dbus_send_init() < 0)
		return -1;

	_W("send_app_launch_signal, pid: %d, appid: %s", pid, appid);

	msg = dbus_message_new_signal(AUL_APP_STATUS_DBUS_PATH,
			AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
			AUL_APP_STATUS_DBUS_LAUNCH_REQUEST);
	if (!msg) {
		_E("Could not create DBus Message.");
		ret = -1;
		goto end;
	}

	if (!dbus_message_append_args(msg,
			DBUS_TYPE_INT32, &pid,
			DBUS_TYPE_STRING, &appid,
			DBUS_TYPE_STRING, &pkgid,
			DBUS_TYPE_STRING, &type,
			DBUS_TYPE_INVALID)) {
		_E("Failed to append a D-Bus Message.");
		ret = -1;
	}

	if (!dbus_connection_send(send_conn, msg, &serial)) {
		_E("Failed to send a D-Bus Message.");
		ret = -1;
	}

	dbus_connection_flush(send_conn);

end:
	if (msg) {
		dbus_message_unref(msg);
	}
	return ret;
}

SLPAPI int aul_send_app_resume_request_signal(int pid, const char *appid, const char *pkgid, const char *type)
{
	DBusMessage *msg = NULL;
	dbus_uint32_t serial = 0;
	const char *empty_string = "";

	int ret = -1;

	if (__app_dbus_send_init() < 0)
		return -1;

	_W("send_app_resume_signal, pid: %d, appid: %s", pid, appid);

	msg = dbus_message_new_signal(AUL_APP_STATUS_DBUS_PATH,
			AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
			AUL_APP_STATUS_DBUS_RESUME_REQUEST);
	if (!msg) {
		_E("Could not create DBus Message.");
		ret = -1;
		goto end;
	}

	if (appid) {
		if (!dbus_message_append_args(msg,
				DBUS_TYPE_INT32, &pid,
				DBUS_TYPE_STRING, &appid,
				DBUS_TYPE_STRING, &pkgid,
				DBUS_TYPE_STRING, &type,
				DBUS_TYPE_INVALID)) {
			_E("Failed to append a D-Bus Message.");
			ret = -1;
		}
	} else {
		if (!dbus_message_append_args(msg,
				DBUS_TYPE_INT32, &pid,
				DBUS_TYPE_STRING, &empty_string,
				DBUS_TYPE_STRING, &empty_string,
				DBUS_TYPE_STRING, &empty_string,
				DBUS_TYPE_INVALID)) {
			_E("Failed to append a D-Bus Message.");
			ret = -1;
		}
	}

	if (!dbus_connection_send(send_conn, msg, &serial)) {
		_E("Failed to send a D-Bus Message.");
		ret = -1;
	}

	dbus_connection_flush(send_conn);

end:
	if (msg) {
		dbus_message_unref(msg);
	}

	return ret;
}

SLPAPI int aul_send_app_terminate_request_signal(int pid, const char *appid, const char *pkgid, const char *type)
{
	DBusMessage *msg = NULL;
	dbus_uint32_t serial = 0;
	const char *empty_string = "";

	int ret = -1;

	if (__app_dbus_send_init() < 0)
		return -1;

	msg = dbus_message_new_signal(AUL_APP_STATUS_DBUS_PATH,
			AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
			AUL_APP_STATUS_DBUS_TERMINATE_REQUEST);
	if (!msg) {
		_E("Could not create DBus Message.");
		ret = -1;
		goto end;
	}

	if (appid) {
		if (!dbus_message_append_args(msg,
				DBUS_TYPE_INT32, &pid,
				DBUS_TYPE_STRING, &appid,
				DBUS_TYPE_STRING, &pkgid,
				DBUS_TYPE_STRING, &type,
				DBUS_TYPE_INVALID)) {
			_E("Failed to append a D-Bus Message.");
			ret = -1;
		}
	} else {
		if (!dbus_message_append_args(msg,
				DBUS_TYPE_INT32, &pid,
				DBUS_TYPE_STRING, &empty_string,
				DBUS_TYPE_STRING, &empty_string,
				DBUS_TYPE_STRING, &empty_string,
				DBUS_TYPE_INVALID)) {
			_E("Failed to append a D-Bus Message.");
			ret = -1;
		}
	}

	if (!dbus_connection_send(send_conn, msg, &serial)) {
		_E("Failed to send a D-Bus Message.");
		ret = -1;
	}

	dbus_connection_flush(send_conn);

end:
	if (msg) {
		dbus_message_unref(msg);
	}

	return ret;

}

SLPAPI int aul_send_app_status_change_signal(int pid, const char *appid, const char *pkgid, const char *status, const char *type)
{
	DBusMessage *msg = NULL;
	dbus_uint32_t serial = 0;
	const char *empty_string = "";

	int ret = -1;

	_W("send_app_status_change_signal, pid: %d, appid: %s, status: %s", pid, appid, status);

	if (__app_dbus_send_init() < 0)
		return -1;

	msg = dbus_message_new_signal(AUL_APP_STATUS_DBUS_PATH,
			AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
			AUL_APP_STATUS_DBUS_STATUS_CHANGE);
	if (!msg) {
		_E("Could not create DBus Message.");
		ret = -1;
		goto end;
	}

	if (appid) {
		if (!dbus_message_append_args(msg,
				DBUS_TYPE_INT32, &pid,
				DBUS_TYPE_STRING, &appid,
				DBUS_TYPE_STRING, &pkgid,
				DBUS_TYPE_STRING, &status,
				DBUS_TYPE_STRING, &type,
				DBUS_TYPE_INVALID)) {
			_E("Failed to append a D-Bus Message.");
			ret = -1;
		}
	} else {
		if (!dbus_message_append_args(msg,
				DBUS_TYPE_INT32, &pid,
				DBUS_TYPE_STRING, &empty_string,
				DBUS_TYPE_STRING, &empty_string,
				DBUS_TYPE_STRING, &status,
				DBUS_TYPE_STRING, &type,
				DBUS_TYPE_INVALID)) {
			_E("Failed to append a D-Bus Message.");
			ret = -1;
		}
	}

	if (!dbus_connection_send(send_conn, msg, &serial)) {
		_E("Failed to send a D-Bus Message.");
		ret = -1;
	}

	dbus_connection_flush(send_conn);

end:
	if (msg) {
		dbus_message_unref(msg);
	}

	return ret;
}

SLPAPI int aul_send_app_terminated_signal(int pid)
{
	DBusMessage *msg = NULL;
	dbus_uint32_t serial = 0;

	int ret = -1;

	if (__app_dbus_send_init() < 0)
		return -1;

	msg = dbus_message_new_signal(AUL_APP_STATUS_DBUS_PATH,
			AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
			AUL_APP_STATUS_DBUS_TERMINATED);
	if (!msg) {
		_E("Could not create DBus Message.");
		ret = -1;
		goto end;
	}

	if (!dbus_message_append_args(msg,
			DBUS_TYPE_INT32, &pid,
			DBUS_TYPE_INVALID)) {
		_E("Failed to append a D-Bus Message.");
		ret = -1;
	}

	if (!dbus_connection_send(send_conn, msg, &serial)) {
		_E("Failed to send a D-Bus Message.");
		ret = -1;
	}

	dbus_connection_flush(send_conn);

end:
	if (msg) {
		dbus_message_unref(msg);
	}
	return ret;
}

SLPAPI int aul_send_app_group_signal(int owner_pid, int child_pid, const char *child_pkgid)
{
	DBusMessage *msg = NULL;
	dbus_uint32_t serial = 0;
	const char  *empty_string = "";

	int ret = -1;

	_W("send_app_group_signal, owner: %d, child: %d", owner_pid, child_pid);

	if (__app_dbus_send_init() < 0)
		return -1;

	msg = dbus_message_new_signal(AUL_APP_STATUS_DBUS_PATH,
			AUL_APP_STATUS_DBUS_SIGNAL_INTERFACE,
			AUL_APP_STATUS_DBUS_GROUP);
	if (!msg) {
		_E("Could not create DBus Message.");
		ret = -1;
		goto end;
	}

	if (child_pkgid) {
		if (!dbus_message_append_args(msg,
					DBUS_TYPE_INT32, &owner_pid,
					DBUS_TYPE_INT32, &child_pid,
					DBUS_TYPE_STRING, &child_pkgid,
					DBUS_TYPE_INVALID)) {
			_E("Failed to append a D-Bus Message.");
			ret = -1;
		}
	} else {
		if (!dbus_message_append_args(msg,
					DBUS_TYPE_INT32, &owner_pid,
					DBUS_TYPE_INT32, &child_pid,
					DBUS_TYPE_STRING, &empty_string,
					DBUS_TYPE_INVALID)) {
			_E("Failed to append a D-Bus Message.");
			ret = -1;
		}
	}

	if (!dbus_connection_send(send_conn, msg, &serial)) {
		_E("Failed to send a D-Bus Message.");
		ret = -1;
	}

	dbus_connection_flush(send_conn);

end:
	if (msg) {
		dbus_message_unref(msg);
	}

	return ret;
}
