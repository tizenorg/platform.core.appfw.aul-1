/*
Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved 
PROPRIETARY/CONFIDENTIAL
This software is the confidential and proprietary information of 
SAMSUNG ELECTRONICS ("Confidential Information"). You agree and acknowledge that 
this software is owned by Samsung and you 
shall not disclose such Confidential Information and shall 
use it only in accordance with the terms of the license agreement 
you entered into with SAMSUNG ELECTRONICS.  SAMSUNG make no 
representations or warranties about the suitability 
of the software, either express or implied, including but not 
limited to the implied warranties of merchantability, fitness for 
a particular purpose, or non-infringement. 
SAMSUNG shall not be liable for any damages suffered by licensee arising out of or 
related to this software.
*/

#include <glib.h>
#include "aul_dbus.h"
#include <sys/time.h>
#include <stdlib.h>

#define MAX_LOCAL_BUFSZ 128

void request_cb(DBusPendingCall *pc, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	char *str;

	reply = dbus_pending_call_steal_reply(pc);
	dbus_pending_call_unref(pc);

	dbus_error_init(&error);

	if (!dbus_message_get_args(reply, &error,
				   DBUS_TYPE_STRING, &str, DBUS_TYPE_INVALID))
		_E("Failed to complete call");

	printf("filename = %s\n", str);

	dbus_message_unref(reply);

	exit(0);
}

int main(int argc, char **argv)
{
	DBusConnection *bus;
	DBusError error;
	DBusMessage *message;
	DBusPendingCall *pc;
	GMainLoop *loop;
	dbus_bool_t ret;

	char tmp[MAX_LOCAL_BUFSZ];
	char *s;
	struct timeval tv;

	loop = g_main_loop_new(NULL, FALSE);

	dbus_error_init(&error);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (bus == NULL)
		_E("Failed to open bus to bus")

		    dbus_connection_setup_with_g_main(bus, NULL);

	message = dbus_message_new_method_call (
			SERVICE_NAME,PATH_NAME,INTERFACE_NAME,
			METHOD_NAME);

	gettimeofday(&tv, NULL);
	snprintf(tmp, MAX_LOCAL_BUFSZ, "%ld/%ld", tv.tv_sec, tv.tv_usec);
	s = tmp;

	dbus_message_append_args(message,
				 DBUS_TYPE_STRING, &s, DBUS_TYPE_INVALID);

	ret = dbus_connection_send_with_reply(bus, message, &pc, INT_MAX);
	if (!ret) {
		_E("dbus_connection_send_with_reply() failed.");
		dbus_message_unref(message);
		return -1;
	}
	if (!dbus_pending_call_set_notify(pc, request_cb, NULL, NULL))
		_E("pending call set fail");

	dbus_message_unref(message);

	printf("wait result\n");

	g_main_loop_run(loop);

	return 0;
}

