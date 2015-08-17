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

#include <sys/signalfd.h>
#include "launch.h"
#include "aul_util.h"
#include "app_signal.h"

static DBusConnection *bus = NULL;
sigset_t oldmask;

extern void __sigterm_handler(int signo);

static inline void __socket_garbage_collector()
{
	DIR *dp;
	struct dirent *dentry;
	char tmp[MAX_LOCAL_BUFSZ];

	dp = opendir(AUL_SOCK_PREFIX);
	if (dp == NULL)
		return;

	while ((dentry = readdir(dp)) != NULL) {
		if (!isdigit(dentry->d_name[0]))
			continue;

		snprintf(tmp, MAX_LOCAL_BUFSZ, "/proc/%s", dentry->d_name);
		if (access(tmp, F_OK) < 0) {	/* Flawfinder: ignore */
			snprintf(tmp, MAX_LOCAL_BUFSZ, "%s/%s", AUL_SOCK_PREFIX,
				 dentry->d_name);
			unlink(tmp);
			continue;
		}
	}
	closedir(dp);
}

static inline int __send_app_dead_signal_amd(int dead_pid) {
	bundle* kb=NULL;
	char tmpbuf[MAX_PID_STR_BUFSZ];
	int ret;

	// send signal to AMD daemon using direct request
	kb=bundle_create();
	if (kb==NULL) {
		_E("bundle creation failed");
		return -1;
	}

	snprintf(tmpbuf, MAX_PID_STR_BUFSZ, "%d", dead_pid);
	bundle_add(kb,AUL_K_PID,tmpbuf);

	ret=app_send_cmd_with_noreply(AUL_UTIL_PID, APP_DEAD_SIGNAL,kb);

	if (ret) {
		_E("unable to send dead signal to amd proc PID %d",dead_pid);
	}
	else {
		_D("send_app_dead_signal_amd done (pid=%d)\n",dead_pid);
	}

	bundle_free(kb);

	return ret;
}

static inline int __send_app_dead_signal_dbus(int dead_pid)
{
	DBusMessage *message;

	// send over session dbus for other applications
	if (bus == NULL)
		return -1;

	message = dbus_message_new_signal(AUL_DBUS_PATH,
					  AUL_DBUS_SIGNAL_INTERFACE,
					  AUL_DBUS_APPDEAD_SIGNAL);

	if (dbus_message_append_args(message,
				     DBUS_TYPE_UINT32, &dead_pid,
				     DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(bus, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	_D("send_app_dead_signal_dbus done (pid=%d)\n",dead_pid);

	return 0;
}

static inline int __send_app_launch_signal_dbus(int launch_pid)
{
	DBusMessage *message;

	if (bus == NULL)
		return -1;

	message = dbus_message_new_signal(AUL_DBUS_PATH,
					  AUL_DBUS_SIGNAL_INTERFACE,
					  AUL_DBUS_APPLAUNCH_SIGNAL);

	if (dbus_message_append_args(message,
				     DBUS_TYPE_UINT32, &launch_pid,
				     DBUS_TYPE_INVALID) == FALSE) {
		_E("Failed to load data error");
		return -1;
	}

	if (dbus_connection_send(bus, message, NULL) == FALSE) {
		_E("dbus send error");
		return -1;
	}

	dbus_connection_flush(bus);
	dbus_message_unref(message);

	_D("send_app_launch_signal_dbus done (pid=%d)",launch_pid);

	return 0;
}

static int __sigchild_action(void *data)
{
	pid_t dead_pid;
	char buf[MAX_LOCAL_BUFSZ];

	dead_pid = (pid_t) data;
	if (dead_pid <= 0)
		goto end;

	__send_app_dead_signal_amd(dead_pid);
	__send_app_dead_signal_dbus(dead_pid);

	snprintf(buf, MAX_LOCAL_BUFSZ, "%s/%d", AUL_SOCK_PREFIX, dead_pid);
	unlink(buf);

	__socket_garbage_collector();
 end:
	return 0;
}

static void __agent_sig_child(int sigchld_fd)
{
	struct signalfd_siginfo info;
	ssize_t s;
	int status;
	pid_t child_pid;
	pid_t child_pgid;

	s = read(sigchld_fd, &info, sizeof(struct signalfd_siginfo));
	if (s != sizeof(struct signalfd_siginfo)) {
		_E("error reading sigchld info");
		return;
	}

	child_pgid = getpgid(info.ssi_pid);
	_D("dead_pid = %d pgid = %d", info.ssi_pid, child_pgid);

	while ((child_pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (child_pid == child_pgid)
			killpg(child_pgid, SIGKILL);
		__sigchild_action((void *)child_pid);
	}

	return;
}

static inline int __signal_init(void)
{
	int i;
	DBusError error;

	dbus_error_init(&error);
	dbus_threads_init_default();
	bus = dbus_bus_get_private(DBUS_BUS_SESSION, &error);
	if (!bus) {
		_E("Failed to connect to the D-BUS daemon: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}

	for (i = 0; i < _NSIG; i++) {
		switch (i) {
			/* controlled by sys-assert package*/
		case SIGQUIT:
		case SIGILL:
		case SIGABRT:
		case SIGBUS:
		case SIGFPE:
		case SIGSEGV:
		case SIGPIPE:
			break;
		case SIGTERM:
			signal(SIGTERM, __sigterm_handler);
			break;
		default:
			signal(i, SIG_DFL);
			break;
		}
	}

	return 0;
}

static inline int __signal_get_sigchld_fd(void)
{
	sigset_t mask;
	int sfd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);

	if (sigprocmask(SIG_BLOCK, &mask, &oldmask) == -1)
		_E("failed to sigprocmask");

	sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd == -1) {
		_E("failed to create signal for SIGCHLD");
		return -1;
	}

	return sfd;
}

static inline int __signal_unblock_sigchld(void)
{
	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0) {
		_E("SIG_SETMASK error");
		return -1;
	}

	_D("SIGCHLD unblocked");
	return 0;
}

static inline int __signal_fini(void)
{
	if (bus)
		dbus_connection_close(bus);

#ifndef PRELOAD_ACTIVATE
	int i;
	for (i = 0; i < _NSIG; i++)
		signal(i, SIG_DFL);
#endif
	return 0;
}

