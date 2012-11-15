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

#include <stdio.h>
#include <glib.h>
#include "aul_dbus.h"
#include "aul.h"
#include <sys/time.h>
#include <stdlib.h>

#define MAX_LOCAL_BUFSZ 128

gboolean result_func(gpointer data)
{
	char *str;
	DBusMessage *reply;
	DBusConnection *bus;
	DBusError error;
	DBusMessage *msg;

	msg = data;

	dbus_error_init(&error);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);

	reply = dbus_message_new_method_return(msg);
	dbus_message_unref(msg);
	str = "picture0.jpg";

	dbus_message_append_args(reply, DBUS_TYPE_STRING,
				 &str, DBUS_TYPE_INVALID);

	dbus_connection_send(bus, reply, NULL);
	dbus_message_unref(reply);

	return 0;
}

void create_take_picture_ui(DBusMessage *msg)
{
	/* simulate, take photo and save time is 30 sec.*/
	g_timeout_add(5 * 1000, result_func, msg);
}

static DBusHandlerResult
dbus_handler(DBusConnection *connection,
	     DBusMessage *message, void *user_data)
{
	DBusMessage *msg;
	char *s;
	DBusError error;
	struct timeval tv;
	struct timeval cur;
	struct timeval res;

	if (dbus_message_is_method_call(message, INTERFACE_NAME, METHOD_NAME)) {
		dbus_error_init(&error);
		msg = dbus_message_ref(message);
		/* real draw */
		if (dbus_message_get_args
		    (message, &error, DBUS_TYPE_STRING, &s,
		     DBUS_TYPE_INVALID)) {
			sscanf(s, "%ld/%ld", &tv.tv_sec, &tv.tv_usec);
			gettimeofday(&cur, NULL);
			timersub(&cur, &tv, &res);
			printf("=================================\n");
			printf("launched time = %ld sec %ld msec\n", res.tv_sec,
			       res.tv_usec / 1000);
			printf("=================================\n");
		}
		create_take_picture_ui(msg);
		return DBUS_HANDLER_RESULT_HANDLED;
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static int init_dbus()
{
	DBusConnection *bus;
	DBusError error;
	char rules[MAX_LOCAL_BUFSZ];

	dbus_error_init(&error);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (!bus)
		_E("couldn't access session bus");

	dbus_connection_setup_with_g_main(bus, NULL);

	dbus_bus_request_name(bus, SERVICE_NAME, 0, &error);
	if (dbus_error_is_set(&error))
		_E("couldn't request name");

	snprintf(rules, MAX_LOCAL_BUFSZ,
		 "path='%s',type='method_call',interface='%s'",
		 PATH_NAME, INTERFACE_NAME);
	dbus_bus_add_match(bus, rules, &error);

	if (!dbus_connection_add_filter(bus, dbus_handler, NULL, NULL))
		_E("couldn't add filter");

	return 0;
}

static int aul_handler(aul_type type, bundle *kb, void *data)
{
	const char *tmp;
	struct timeval tv;
	struct timeval cur;
	struct timeval res;

	switch (type) {
	case AUL_START:
		printf("app start & add dbus\n");
		tmp = bundle_get_val(kb, AUL_K_STARTTIME);
		if (tmp != NULL) {
			sscanf(tmp, "%ld/%ld", &tv.tv_sec, &tv.tv_usec);
			gettimeofday(&cur, NULL);
			timersub(&cur, &tv, &res);
			printf("=================================\n");
			printf("launched time by aul= %ld sec %ld msec\n",
			       res.tv_sec, res.tv_usec / 1000);
			printf("=================================\n");
		}
		/* DONOT draw if auto-activated by dbus */
		init_dbus();
		break;
	case AUL_RESUME:
		break;
	case AUL_TERMINATE:
		exit(0);
		break;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	GMainLoop *loop;

	loop = g_main_loop_new(NULL, FALSE);

	aul_launch_init(aul_handler, NULL);
	aul_launch_argv_handler(argc, argv);

	g_main_loop_run(loop);

	return 0;
}

