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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <poll.h>
#include <aul.h>
#include <glib.h>
#include <bundle.h>
#include <tzplatform_config.h>

#include "amd_config.h"
#include "simple_util.h"
#include "app_sock.h"
#include "aul_util.h"
#include "amd_request.h"
#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_status.h"


#define INHOUSE_UID     tzplatform_getuid(TZ_USER_NAME)

struct appinfomgr *_raf;

static int __send_result_to_client(int fd, int res);
static gboolean __request_handler(gpointer data);

extern int __app_dead_handler(int pid, uid_t user);
extern int __agent_dead_handler(uid_t user);

static int __send_result_to_client(int fd, int res)
{
	if (send(fd, &res, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}
	close(fd);
	return 0;
}

static void __real_send(int clifd, int ret)
{
	if (send(clifd, &ret, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE) {
			_E("send failed due to EPIPE.\n");
		}
		_E("send fail to client");
	}

	close(clifd);
}

static int __get_caller_pid(bundle *kb)
{
	const char *pid_str;
	int pid;

	pid_str = bundle_get_val(kb, AUL_K_ORG_CALLER_PID);
	if(pid_str)
		goto end;

	pid_str = bundle_get_val(kb, AUL_K_CALLER_PID);
	if (pid_str == NULL)
		return -1;

end:
	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	return pid;
}

static int __foward_cmd(int cmd, bundle *kb, int cr_pid)
{
	int pid;
	int pgid;
	char tmp_pid[MAX_PID_STR_BUFSZ];
	int datalen;
	bundle_raw *kb_data;
	int res;

	if ((pid = __get_caller_pid(kb)) < 0)
			return AUL_R_ERROR;

	pgid = getpgid(cr_pid);
	if(pgid > 0) {
		snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", pgid);
		bundle_del(kb,AUL_K_CALLEE_PID);
		bundle_add(kb, AUL_K_CALLEE_PID, tmp_pid);
	}

	bundle_encode(kb, &kb_data, &datalen);
	if ((res = __app_send_raw_with_noreply(pid, cmd, kb_data, datalen)) < 0)
		res = AUL_R_ERROR;

	free(kb_data);

	return res;
}

static int __app_process_by_pid(int cmd,
	const char *pkg_name, struct ucred *cr, int clifd)
{
	int pid;
	int ret = -1;
	int dummy;

	if (pkg_name == NULL)
		return -1;

	pid = atoi(pkg_name);
	if (pid <= 1) {
		_E("invalid pid");
		return -1;
	}

	switch (cmd) {
	case APP_RESUME_BY_PID:
		ret = _resume_app(pid, clifd);
		break;
	case APP_TERM_BY_PID:
		ret = _term_app(pid);
		break;
	case APP_KILL_BY_PID:
		if ((ret = _send_to_sigkill(pid)) < 0)
			_E("fail to killing - %d\n", pid);
		break;
	case APP_TERM_REQ_BY_PID:
		if ((ret = __app_send_raw(pid, APP_TERM_REQ_BY_PID, (unsigned char *)&dummy, sizeof(int))) < 0) {
			_D("terminate req packet send error");
		}
		break;
	case APP_TERM_BY_PID_ASYNC:
		if ((ret = __app_send_raw_with_noreply(pid, cmd, (unsigned char *)&dummy, sizeof(int))) < 0) {
			_D("terminate req packet send error");
		}
		__real_send(clifd, ret);
		break;
	}

	return ret;
}

static int __get_pid_cb(void *user_data, const char *group, pid_t pid)
{
	int *sz = user_data;

	_D("%s: %d : %d", *sz, pid);
	*sz = 1; /* 1 is enough */

	return -1; /* stop the iteration */
}

static int __release_srv(uid_t caller_uid, const char *filename)
{
	int r;
	const struct appinfo *ai;

	ai = (struct appinfo *)appinfo_find(caller_uid, filename);
	if (!ai) {
		SECURE_LOGE("release service: '%s' not found", filename);
		return -1;
	}

	r = appinfo_get_boolean(ai, AIT_RESTART);
	if (r == 1) {
		/* Auto restart */
		SECURE_LOGD("Auto restart set: '%s'", filename);
		return _start_srv(ai, NULL);
	}

	service_release(filename);

	return 0;
}

static int __handle_dead_signal(bundle *kb, int clifd, struct ucred *pcr)
{
	int ret = -1;
	const char *pid_str;
	int pid = 0;

	/* check the credentials from the caller: must be the amd agent */
	char *caller = __proc_get_exe_bypid(pcr->pid);
	if (!caller) {
		_D("handle_dead_signal: unable to get caller exe");
		return -1;
	}

	if (strcmp(caller, "/usr/bin/amd_session_agent")) {
		_D("handle_dead_signal: caller is not amd session agent, %d : '%s'",
				pcr->pid, caller);
		free(caller);
		return -1;
	}
	free(caller);

	/* get app pid from bundle */
	pid_str = bundle_get_val(kb, AUL_K_PID);
	if (!pid_str)
		return -1;

	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	_D("APP_DEAD_SIGNAL : %d", pid);

	ret = __app_dead_handler(pid, pcr->uid);

	return ret;
}

static void __handle_agent_dead_signal(struct ucred *pcr)
{
	/* TODO: check the credentials from the caller: must be the amd agent */

	_D("AGENT_DEAD_SIGNAL : %d", pcr->uid);
	__agent_dead_handler(pcr->uid);
}

static gboolean __request_handler(gpointer data)
{
	GPollFD *gpollfd = (GPollFD *) data;
	int fd = gpollfd->fd;
	app_pkt_t *pkt;
	int clifd;
	struct ucred cr;
	int *status;
	int ret = -1;
	int free_pkt = 1;
	char *appid;
	/*char *app_path;
	char *tmp_pid;*/
	int pid;
	bundle *kb = NULL;
	item_pkt_t *item;
	pkt_t *pkt_uid;

	if ((pkt = __app_recv_raw(fd, &clifd, &cr)) == NULL) {
		_E("recv error");
		return FALSE;
	}

	switch (pkt->cmd) {
		case APP_OPEN:
		case APP_RESUME:
		case APP_START:
		case APP_START_RES:
			kb = bundle_decode(pkt->data, pkt->len);
			appid = (char *)bundle_get_val(kb, AUL_K_APPID);
			if (cr.uid == 0) {
				_E("Root user request to start app assumming this is done by system deamon... Please fix it...switch to DEFAULT_USER");
				ret = _start_app(appid, kb, pkt->cmd, cr.pid, DEFAULT_USER, clifd);
			}
			else {
				ret = _start_app(appid, kb, pkt->cmd, cr.pid, cr.uid, clifd);
			}
			if(ret > 0) {
				item = calloc(1, sizeof(item_pkt_t));
				item->pid = ret;
				item->uid = cr.uid;
				strncpy(item->appid, appid, 511);
				free_pkt = 0;

				pkt_uid = calloc(1, sizeof(pkt_t));
				pkt_uid->caller_uid = cr.uid;
				pkt_uid->pkt = pkt;

				g_timeout_add(1200, __add_item_running_list, item);
			}

			if (kb != NULL)
				bundle_free(kb), kb = NULL;
			break;
		case APP_RESULT:
		case APP_CANCEL:
			kb = bundle_decode(pkt->data, pkt->len);
			ret = __foward_cmd(pkt->cmd, kb, cr.pid);
			//__real_send(clifd, ret);
			close(clifd);
			break;
		case APP_TERM_BY_PID:
		case APP_RESUME_BY_PID:
		case APP_KILL_BY_PID:
		case APP_TERM_REQ_BY_PID:
		case APP_TERM_BY_PID_ASYNC:
			kb = bundle_decode(pkt->data, pkt->len);
			appid = (char *)bundle_get_val(kb, AUL_K_APPID);
			ret = __app_process_by_pid(pkt->cmd, appid, &cr, clifd);
			break;
		case APP_RUNNING_INFO:
			_status_send_running_appinfo(clifd);
			break;
		case APP_IS_RUNNING:
			appid = malloc(MAX_PACKAGE_STR_SIZE);
			strncpy(appid, (const char*)pkt->data, MAX_PACKAGE_STR_SIZE-1);
			ret = _status_app_is_running(appid, cr.uid);
			SECURE_LOGD("APP_IS_RUNNING : %s : %d",appid, ret);
			__send_result_to_client(clifd, ret);
			free(appid);
			break;
		case APP_GET_APPID_BYPID:
			memcpy(&pid, pkt->data, pkt->len);
			ret = _status_get_appid_bypid(clifd, pid);
			_D("APP_GET_APPID_BYPID : %d : %d", pid, ret);
			break;
		case APP_KEY_RESERVE:
			// support for key events has been removed (sdx-20140813)
			__send_result_to_client(clifd, 0);
			break;
		case APP_KEY_RELEASE:
			// support for key events has been removed (sdx-20140813)
			__send_result_to_client(clifd, 0);
			break;
		case APP_STATUS_UPDATE:
			status = (int *)pkt->data;
			ret = _status_update_app_info_list(cr.pid, *status, cr.uid);
			//__send_result_to_client(clifd, ret);
			close(clifd);
			break;
		case APP_RELEASED:
			appid = malloc(MAX_PACKAGE_STR_SIZE);
			strncpy(appid, (const char*)pkt->data, MAX_PACKAGE_STR_SIZE-1);
			ret = __release_srv(cr.uid,appid);
			__send_result_to_client(clifd, ret);
			free(appid);
			break;
		case APP_RUNNING_LIST_UPDATE:
			/*kb = bundle_decode(pkt->data, pkt->len);
			  appid = (char *)bundle_get_val(kb, AUL_K_APPID);
			  app_path = (char *)bundle_get_val(kb, AUL_K_EXEC);
			  tmp_pid = (char *)bundle_get_val(kb, AUL_K_PID);
			  pid = atoi(tmp_pid);
			  ret = _status_add_app_info_list(appid, app_path, pid);*/
			ret = 0;
			__send_result_to_client(clifd, ret);
			break;
		case APP_DEAD_SIGNAL:
			_D("APP_DEAD_SIGNAL");
			kb = bundle_decode(pkt->data, pkt->len);
			ret = __handle_dead_signal(kb, clifd, &cr);
			close(clifd);
			break;
		case AGENT_DEAD_SIGNAL:
			_D("AMD_AGENT_DEAD_SIGNAL");
			__handle_agent_dead_signal(&cr);
			close(clifd);
			break;
		default:
			_E("no support packet");
			close(clifd);
	}

	if (free_pkt)
		free(pkt);

	if (kb != NULL)
		bundle_free(kb), kb = NULL;

	return TRUE;
}

static gboolean __au_glib_check(GSource *src)
{
	GSList *fd_list;
	GPollFD *tmp;

	fd_list = src->poll_fds;
	do {
		tmp = (GPollFD *) fd_list->data;
		if ((tmp->revents & (POLLIN | POLLPRI)))
			return TRUE;
		fd_list = fd_list->next;
	} while (fd_list);

	return FALSE;
}

static gboolean __au_glib_dispatch(GSource *src, GSourceFunc callback,
		gpointer data)
{
	callback(data);
	return TRUE;
}

static gboolean __au_glib_prepare(GSource *src, gint *timeout)
{
	return FALSE;
}

static GSourceFuncs funcs = {
	.prepare = __au_glib_prepare,
	.check = __au_glib_check,
	.dispatch = __au_glib_dispatch,
	.finalize = NULL
};

int _requset_init(struct amdmgr *amd)
{
	int fd;
	int r;
	GPollFD *gpollfd;
	GSource *src;

	fd = __create_sock_activation();
	if (fd == -1) {
		_D("Create server socket without socket activation");
		fd = __create_server_sock(AUL_UTIL_PID);
	}

	src = g_source_new(&funcs, sizeof(GSource));

	gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc) __request_handler,
			(gpointer) gpollfd, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);

	r = g_source_attach(src, NULL);
	if (r  == 0)
	{
		/* TODO: error handle*/
		return -1;
	}

	_raf = amd->af;

	return 0;
}


