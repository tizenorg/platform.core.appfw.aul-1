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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <glib.h>
#include <dbus/dbus.h>

#include <bundle_internal.h>

#include "aul.h"
#include "aul_api.h"
#include "aul_socket.h"
#include "perf.h"
#include "simple_util.h"
#include "launch.h"
#include "key.h"
#include "aul_util.h"
#include "app_signal.h"

#define TEP_ISMOUNT_MAX_RETRY_CNT 20

static int aul_initialized = 0;
static int aul_fd;
static void *__window_object = NULL;
static void *__bg_object = NULL;
static void *__conformant_object = NULL;

static int (*_aul_handler) (aul_type type, bundle *kb, void *data) = NULL;
static void *_aul_data;

static int app_resume();
static int app_terminate();
static void __clear_internal_key(bundle *kb);
static inline void __set_stime(bundle *kb);
static int __app_start_internal(gpointer data);
static int __app_launch_local(bundle *b);
static int __send_result_to_launchpad(int fd, int res);

static data_control_provider_handler_fn __dc_handler = NULL;
extern  int aul_launch_fini();

int aul_is_initialized()
{
	return aul_initialized;
}

int __call_aul_handler(aul_type type, bundle *kb)
{
	if (_aul_handler)
		_aul_handler(type, kb, _aul_data);
	return 0;
}

int app_start(bundle *kb)
{
	const char *str = NULL;

	_app_start_res_prepare(kb);
	__call_aul_handler(AUL_START, kb);
	/* Handle the DataControl callback */
	str = bundle_get_val(kb, AUL_K_DATA_CONTROL_TYPE);
	if (str != NULL && strcmp(str, "CORE") == 0) {
		if (__dc_handler != NULL)
			__dc_handler(kb, 0, NULL); /* bundle, request_id, data */
	}

	return 0;
}

static int app_resume()
{
	__call_aul_handler(AUL_RESUME, NULL);
	return 0;
}

static int app_terminate()
{
	__call_aul_handler(AUL_TERMINATE, NULL);
	return 0;
}

static int bgapp_terminate(void)
{
	__call_aul_handler(AUL_TERMINATE_BGAPP, NULL);
	return 0;
}

static int app_pause(void)
{
	__call_aul_handler(AUL_PAUSE, NULL);
	return 0;
}

static int __get_aul_error(int res)
{
	int ret;

	switch (res) {
	case -EREJECTED:
		ret = AUL_R_EREJECTED;
		break;
	case -ENOENT:
		ret = AUL_R_ENOAPP;
		break;
	case -ENOLAUNCHPAD:
		ret = AUL_R_ENOLAUNCHPAD;
		break;
	case -ETERMINATING:
		ret = AUL_R_ETERMINATING;
		break;
	case -EILLEGALACCESS:
		ret = AUL_R_EILLACC;
		break;
	case -ELOCALLAUNCH_ID:
		ret = AUL_R_LOCAL;
		break;
	case -EAGAIN:
		ret = AUL_R_ETIMEOUT;
		break;
	case -EINVAL:
		ret = AUL_R_EINVAL;
		break;
	case -ECOMM:
		ret = AUL_R_ECOMM;
		break;
	default:
		ret = AUL_R_ERROR;
	}

	return ret;
}

static int __app_send_cmd_with_fd(int pid, int uid, int cmd, bundle *kb, int *ret_fd)
{
	int datalen;
	bundle_raw *kb_data = NULL;
	int res = AUL_R_OK;

	res = bundle_encode(kb, &kb_data, &datalen);
	if (res != BUNDLE_ERROR_NONE)
		return AUL_R_EINVAL;

	if ((res = aul_socket_send_raw_with_fd_reply(pid, uid, cmd, kb_data, datalen, ret_fd)) < 0) {
		switch (res) {
		case -EINVAL:
			res = AUL_R_EINVAL;
			break;
		case -ECOMM:
			res = AUL_R_ECOMM;
			break;
		case -EAGAIN:
			res = AUL_R_ETIMEOUT;
			break;
		case -ELOCALLAUNCH_ID:
			res = AUL_R_LOCAL;
			break;
		case -EILLEGALACCESS:
			res = AUL_R_EILLACC;
			break;
		case -ETERMINATING:
			res = AUL_R_ETERMINATING;
			break;
		case -ENOLAUNCHPAD:
			res = AUL_R_ENOLAUNCHPAD;
			break;
#ifdef _APPFW_FEATURE_APP_CONTROL_LITE
		case -EUGLOCAL_LAUNCH:
			res = AUL_R_UG_LOCAL;
			break;
#endif
		case -EREJECTED:
			res = AUL_R_EREJECTED;
			break;
		default:
			res = AUL_R_ERROR;
		}
	}

	free(kb_data);

	return res;
}

/**
 * @brief	encode kb and send it to 'pid'
 * @param[in]	pid		receiver's pid
 * @param[in]	cmd		message's status (APP_START | APP_RESULT)
 * @param[in]	kb		data
 */
API int app_send_cmd(int pid, int cmd, bundle *kb)
{
	return app_send_cmd_for_uid(pid, getuid(), cmd, kb);
}

API int app_send_cmd_for_uid(int pid, uid_t uid, int cmd, bundle *kb)
{
	int datalen;
	bundle_raw *kb_data;
	int res;

	bundle_encode(kb, &kb_data, &datalen);
	if ((res = aul_socket_send_raw(pid, uid, cmd, kb_data, datalen)) < 0)
		res = __get_aul_error(res);
	free(kb_data);

	return res;
}

API int app_send_cmd_with_noreply(int pid, int cmd, bundle *kb)
{
	int datalen;
	bundle_raw *kb_data;
	int res;

	bundle_encode(kb, &kb_data, &datalen);
	res = aul_socket_send_raw_async(pid, getuid(), cmd, kb_data, datalen);
	if (res > 0) {
		close(res);
		res = 0;
	} else {
		res = __get_aul_error(res);
	}

	free(kb_data);

	return res;
}

static void __clear_internal_key(bundle *kb)
{
	bundle_del(kb, AUL_K_CALLER_PID);
	bundle_del(kb, AUL_K_APPID);
	bundle_del(kb, AUL_K_WAIT_RESULT);
	bundle_del(kb, AUL_K_SEND_RESULT);
	bundle_del(kb, AUL_K_ARGV0);
}

static inline void __set_stime(bundle *kb)
{
	struct timeval tv;
	char tmp[MAX_LOCAL_BUFSZ];

	gettimeofday(&tv, NULL);
	snprintf(tmp, MAX_LOCAL_BUFSZ, "%ld/%ld", tv.tv_sec, tv.tv_usec);
	bundle_add(kb, AUL_K_STARTTIME, tmp);
}

static int __app_start_internal(gpointer data)
{
	bundle *kb;

	kb = (bundle *) data;
	app_start(kb);
	bundle_free(kb);

	return 0;
}

static int __app_launch_local(bundle *b)
{
	if (!aul_is_initialized())
		return AUL_R_ENOINIT;

	if (b == NULL)
		_E("bundle for APP_START is NULL");

	if (g_idle_add(__app_start_internal, b) > 0)
		return AUL_R_OK;
	else
		return AUL_R_ERROR;
}

static int __app_resume_local()
{
	if (!aul_is_initialized())
		return AUL_R_ENOINIT;

	app_resume();

	return 0;
}

int app_request_to_launchpad_with_fd(int cmd, const char *appid, bundle *kb, int *fd, int uid)
{
	int must_free = 0;
	int ret = 0;
	bundle *b;

	SECURE_LOGD("launch request : %s", appid);
	if (kb == NULL) {
		kb = bundle_create();
		must_free = 1;
	} else {
		__clear_internal_key(kb);
	}

	ret = __app_send_cmd_with_fd(AUL_UTIL_PID, uid, cmd, kb, fd);

	_D("launch request result : %d", ret);
	if (ret == AUL_R_LOCAL) {
		_E("app_request_to_launchpad : Same Process Send Local");

		switch (cmd) {
		case APP_START:
		case APP_START_RES:
			b = bundle_dup(kb);
			ret = __app_launch_local(b);
			break;
		case APP_OPEN:
		case APP_RESUME:
		case APP_RESUME_BY_PID:
			ret = __app_resume_local();
			break;
		default:
			_E("no support packet");
		}

	}

	/* cleanup */
	if (must_free)
		bundle_free(kb);

	return ret;
}


/**
 * @brief	start caller with kb
 * @return	callee's pid
 */
int app_request_to_launchpad(int cmd, const char *appid, bundle *kb)
{
	return app_request_to_launchpad_for_uid(cmd, appid, kb, getuid());
}

int app_request_to_launchpad_for_uid(int cmd, const char *appid, bundle *kb, uid_t uid)
{
	int must_free = 0;
	int ret = 0;
	bundle *b;

	SECURE_LOGD("launch request : %s", appid);
	if (kb == NULL) {
		kb = bundle_create();
		must_free = 1;
	} else {
		__clear_internal_key(kb);
	}

	bundle_add(kb, AUL_K_APPID, appid);
	__set_stime(kb);
	ret = app_send_cmd_for_uid(AUL_UTIL_PID, uid, cmd, kb);

	_D("launch request result : %d", ret);
	if (ret == AUL_R_LOCAL) {
		_E("app_request_to_launchpad : Same Process Send Local");

		switch (cmd) {
		case APP_START:
		case APP_START_RES:
			b = bundle_dup(kb);
			ret = __app_launch_local(b);
			break;
		case APP_OPEN:
		case APP_RESUME:
		case APP_RESUME_BY_PID:
			ret = __app_resume_local();
			break;
		default:
			_E("no support packet");
		}

	}

	/* cleanup */
	if (must_free)
		bundle_free(kb);

	return ret;
}

static int __send_result_to_launchpad(int fd, int res)
{
	if (send(fd, &res, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
			close(fd);
			return -1;
		}
		_E("send fail to client");
	}
	close(fd);
	return 0;
}

/**
 * @brief	caller & callee's sock handler
 */
int aul_sock_handler(int fd)
{
	app_pkt_t *pkt;
	bundle *kbundle;
	int clifd;
	struct ucred cr;

	const char *pid_str;
	int pid;
	int ret;

	if ((pkt = aul_socket_recv_pkt(fd, &clifd, &cr)) == NULL) {
		_E("recv error");
		return -1;
	}

	if (pkt->cmd != APP_RESULT && pkt->cmd != APP_CANCEL && pkt->cmd != APP_TERM_BY_PID_ASYNC) {
		ret = __send_result_to_launchpad(clifd, 0);
		if (ret < 0) {
			free(pkt);
			return -1;
		}
	} else {
		close(clifd);
	}

	switch (pkt->cmd) {
	case APP_START:	/* run in callee */
	case APP_START_RES:
		kbundle = bundle_decode(pkt->data, pkt->len);
		if (kbundle == NULL)
			goto err;
		app_start(kbundle);
		bundle_free(kbundle);
		break;

	case APP_OPEN:	/* run in callee */
	case APP_RESUME:
	case APP_RESUME_BY_PID:
		app_resume();
		break;

	case APP_TERM_BY_PID:	/* run in callee */
	case APP_TERM_BY_PID_ASYNC:
		app_terminate();
		break;

	case APP_TERM_BGAPP_BY_PID:
		bgapp_terminate();
		break;

	case APP_TERM_REQ_BY_PID:	/* run in callee */
		app_subapp_terminate_request();
		break;

	case APP_RESULT:	/* run in caller */
	case APP_CANCEL:
		kbundle = bundle_decode(pkt->data, pkt->len);
		if (kbundle == NULL)
			goto err;

		pid_str = bundle_get_val(kbundle, AUL_K_CALLEE_PID);
		pid = atoi(pid_str);

		app_result(pkt->cmd, kbundle, pid);
		bundle_free(kbundle);
		break;

	case APP_KEY_EVENT:	/* run in caller */
		kbundle = bundle_decode(pkt->data, pkt->len);
		if (kbundle == NULL)
			goto err;
		app_key_event(kbundle);
		bundle_free(kbundle);
		break;

	case APP_PAUSE_BY_PID:
		app_pause();
		break;

	default:
		_E("no support packet");
	}

	free(pkt);
	return 0;

err:
	free(pkt);
	return -1;
}

int aul_make_bundle_from_argv(int argc, char **argv, bundle **kb)
{
	int ac = 1;

	char *buf = NULL;

	*kb = bundle_create();
	if (*kb == NULL)
		return AUL_R_ERROR;

	if (argv == NULL)
		return AUL_R_OK;

	if ((argv != NULL) && (argv[0] != NULL)) {
		buf = strdup(argv[0]);
		if (NULL == buf) {
			_E("Malloc failed");
			return AUL_R_ERROR;
		}

		bundle_add(*kb, AUL_K_ARGV0, buf);
	}
	if (buf) {		/*Prevent FIX: ID 38717 */
		free(buf);
		buf = NULL;
	}

	while (ac < argc) {
		if (ac + 1 == argc) {
			if (bundle_add(*kb, argv[ac], "") < 0) {
				_E("bundle add error pos - %d", ac);
				return AUL_R_ECANCELED;
			}
		} else {
			if (bundle_add(*kb, argv[ac], argv[ac + 1]) < 0) {
				_E("bundle add error pos - %d", ac);
				return AUL_R_ECANCELED;
			}
		}
		ac = ac + 2;
	}

	return AUL_R_OK;
}

int aul_register_init_callback(
	int (*aul_handler) (aul_type type, bundle *, void *), void *data)
{
	/* Save start handler function in static var */
	_aul_handler = aul_handler;
	_aul_data = data;
	return 0;
}

int aul_initialize()
{
	if (aul_initialized)
		return AUL_R_ECANCELED;

	aul_fd = aul_socket_create_server(getpid(), getuid());
	if (aul_fd < 0) {
		_E("aul_init create sock failed");
		return AUL_R_ECOMM;
	}
	aul_initialized = 1;

	return aul_fd;
}

API void aul_finalize()
{
	aul_launch_fini();

	if (aul_initialized)
		close(aul_fd);

	return;
}

API int aul_request_data_control_socket_pair(bundle *kb, int *fd)
{
	return app_request_to_launchpad_with_fd(APP_GET_SOCKET_PAIR, NULL, kb, fd, getuid());
}

API int aul_launch_app(const char *appid, bundle *kb)
{
	int ret;

	if (appid == NULL)
		return AUL_R_EINVAL;

	ret = app_request_to_launchpad(APP_START, appid, kb);
	return ret;
}

API int aul_launch_app_for_uid(const char *appid, bundle *kb, uid_t uid)
{
	int ret;
	char buf[MAX_PID_STR_BUFSZ];
	if (appid == NULL)
		return AUL_R_EINVAL;
	snprintf(buf, MAX_UID_STR_BUFSZ, "%d", uid);
	bundle_add(kb, AUL_K_TARGET_UID, buf);

	ret = app_request_to_launchpad_for_uid(APP_START, appid, kb, uid);
	return ret;
}

API int aul_open_app(const char *appid)
{
	int ret;

	if (appid == NULL)
		return AUL_R_EINVAL;

	ret = app_request_to_launchpad(APP_OPEN, appid, NULL);
	return ret;
}

API int aul_resume_app(const char *appid)
{
	int ret;

	if (appid == NULL)
		return AUL_R_EINVAL;

	ret = app_request_to_launchpad(APP_RESUME, appid, NULL);
	return ret;
}

API int aul_resume_pid(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_RESUME_BY_PID, pkgname, NULL);
	return ret;
}

API int aul_terminate_pid(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_BY_PID, pkgname, NULL);
	return ret;
}

API int aul_terminate_bgapp_pid(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_BGAPP_BY_PID, pkgname, NULL);
	return ret;
}

API int aul_terminate_pid_without_restart(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_BY_PID_WITHOUT_RESTART, pkgname, NULL);
	return ret;
}

API int aul_terminate_pid_async(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_TERM_BY_PID_ASYNC, pkgname, NULL);
	return ret;
}

API int aul_kill_pid(int pid)
{
	char pkgname[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_KILL_BY_PID, pkgname, NULL);
	return ret;
}

API int aul_set_data_control_provider_cb(data_control_provider_handler_fn handler)
{
	__dc_handler = handler;
	return 0;
}

API int aul_unset_data_control_provider_cb(void)
{
	__dc_handler = NULL;
	return 0;
}

API void aul_set_preinit_window(void *evas_object)
{
	__window_object = evas_object;
}

API void* aul_get_preinit_window(const char *win_name)
{
	return __window_object;
}

API void aul_set_preinit_background(void *evas_object)
{
	__bg_object = evas_object;
}

API void* aul_get_preinit_background(void)
{
	return __bg_object;
}

API void aul_set_preinit_conformant(void *evas_object)
{
	__conformant_object = evas_object;
}

API void* aul_get_preinit_conformant(void)
{
	return __conformant_object;
}

API int aul_pause_app(const char *appid)
{
	int ret;

	if (appid == NULL)
		return AUL_R_EINVAL;

	ret = app_request_to_launchpad(APP_PAUSE, appid, NULL);
	return ret;
}

API int aul_pause_pid(int pid)
{
	char app_pid[MAX_PID_STR_BUFSZ];
	int ret;

	if (pid <= 0)
		return AUL_R_EINVAL;

	snprintf(app_pid, MAX_PID_STR_BUFSZ, "%d", pid);
	ret = app_request_to_launchpad(APP_PAUSE_BY_PID, app_pid, NULL);
	return ret;
}

API int aul_reload_appinfo(void)
{
	char pkgname[MAX_PID_STR_BUFSZ];

	snprintf(pkgname, MAX_PID_STR_BUFSZ, "%d", getpid());

	return app_request_to_launchpad(AMD_RELOAD_APPINFO, pkgname, NULL);
}

API int aul_is_tep_mount_dbus_done(const char *tep_string)
{
	DBusMessage *msg;
	DBusMessage *reply;
	DBusError err;
	int ret = -1;
	int r = -1;

	DBusConnection *conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!conn) {
		_E("dbus_bus_get error");
		return -EBADMSG;
	}

	msg = dbus_message_new_method_call(TEP_BUS_NAME, TEP_OBJECT_PATH,
					TEP_INTERFACE_NAME, TEP_IS_MOUNTED_METHOD);
	if (!msg) {
		_E("dbus_message_new_method_call(%s:%s-%s)", TEP_OBJECT_PATH,
			TEP_INTERFACE_NAME, TEP_IS_MOUNTED_METHOD);
		return ret;
	}

	if (!dbus_message_append_args(msg,
				DBUS_TYPE_STRING, &tep_string,
				DBUS_TYPE_INVALID)) {
		_E("Ran out of memory while constructing args\n");
		dbus_message_unref(msg);
		return ret;
	}

	dbus_error_init(&err);
	reply = dbus_connection_send_with_reply_and_block(conn, msg, 500, &err);
	if (!reply) {
		_E("dbus_connection_send error(%s:%s)", err.name, err.message);
		goto func_out;
	}

	r = dbus_message_get_args(reply, &err, DBUS_TYPE_INT32, &ret,
				DBUS_TYPE_INVALID);
	if (!r) {
		_E("no message : [%s:%s]", err.name, err.message);
		goto func_out;
	}

func_out:
	dbus_message_unref(msg);
	dbus_error_free(&err);
	return ret;
}

API int aul_check_tep_mount(const char *tep_path)
{
	if (tep_path) {
		int rv = -1;
		int cnt = 0;
		while (cnt < TEP_ISMOUNT_MAX_RETRY_CNT) {
			rv = aul_is_tep_mount_dbus_done(tep_path);
			if (rv == 1)
				break;
			usleep(50 * 1000);
			cnt++;
		}
		/* incase after trying 1 sec, not getting mounted then quit */
		if (rv != 1) {
			_E("Not able to mount within 1 sec");
			return -1;
		}
	}
	return 0;
}

API int aul_add_loader(const char *loader_path)
{
	int ret;
	bundle *b;

	if (loader_path == NULL)
		return AUL_R_EINVAL;

	b = bundle_create();
	bundle_add_str(b, AUL_K_LOADER_PATH, loader_path);
	ret = app_send_cmd(AUL_UTIL_PID, APP_ADD_LOADER, b);
	bundle_free(b);

	return ret;
}

API int aul_remove_loader(int loader_id)
{
	char lid[MAX_PID_STR_BUFSZ];
	int ret;
	bundle *b;

	if (loader_id <= 0)
		return AUL_R_EINVAL;

	b = bundle_create();
	snprintf(lid, MAX_PID_STR_BUFSZ, "%d", loader_id);
	bundle_add_str(b, AUL_K_LOADER_ID, lid);
	ret = app_send_cmd(AUL_UTIL_PID, APP_REMOVE_LOADER, b);
	bundle_free(b);

	return ret;
}


