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

#include <glib.h>

#include <aul.h>
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
#include "amd_app_group.h"

#define INHOUSE_UID     tzplatform_getuid(TZ_USER_NAME)

static int __send_result_to_client(int fd, int res);
static gboolean __request_handler(gpointer data);

static int __send_result_data(int fd, int cmd, unsigned char *kb_data, int datalen)
{
	int len;
	int sent = 0;
	int res = 0;
	app_pkt_t *pkt = NULL;

	if (datalen > AUL_SOCK_MAXBUFF - 8) {
		_E("datalen > AUL_SOCK_MAXBUFF\n");
		return -EINVAL;
	}

	pkt = (app_pkt_t *) malloc(sizeof(int) + sizeof(int) + datalen);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, datalen);

	while (sent != AUL_PKT_HEADER_SIZE + datalen) {
		len = send(fd, pkt, AUL_PKT_HEADER_SIZE + datalen - sent, 0);
		if (len <= 0) {
			_E("send error fd:%d (errno %d)", fd, errno);
			close(fd);
			free(pkt);
			return -ECOMM;
		}
		sent += len;
	}

	free(pkt);
	close(fd);

	return res;
}

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
	int ret;
	int dummy;
	char *appid;

	if (pkg_name == NULL)
		return -1;

	pid = atoi(pkg_name);
	if (pid <= 1) {
		_E("invalid pid");
		return -1;
	}

	appid = _status_app_get_appid_bypid(pid);
	if (appid == NULL) {
		_E("pid %d is not an app", pid);
		__real_send(clifd, -1);
		return -1;
	}

	switch (cmd) {
	case APP_RESUME_BY_PID:
		ret = _resume_app(pid, clifd);
		break;
	case APP_TERM_BY_PID:
	case APP_TERM_BY_PID_WITHOUT_RESTART:
		ret = _term_app(pid, clifd);
		break;
	case APP_TERM_BGAPP_BY_PID:
		ret = _term_bgapp(pid, clifd);
		break;
	case APP_KILL_BY_PID:
		if ((ret = _send_to_sigkill(pid)) < 0)
			_E("fail to killing - %d\n", pid);
		__real_send(clifd, ret);
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
	case APP_PAUSE_BY_PID:
		ret = _pause_app(pid, clifd);
		break;
	default:
		_E("unknown command: %d", cmd);
		ret = -1;
	}

	return ret;
}

static int __release_srv(uid_t caller_uid, const char *appid)
{
	int r;
	const struct appinfo *ai;

	ai = (struct appinfo *)appinfo_find(caller_uid, appid);
	if (!ai) {
		SECURE_LOGE("release service: '%s' not found", appid);
		return -1;
	}

	r = appinfo_get_boolean(ai, AIT_RESTART);
	if (r == 1) {
		/* Auto restart */
		SECURE_LOGD("Auto restart set: '%s'", appid);
		return _start_app_local(caller_uid, appid);
	}

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

static void __dispatch_app_group_add(int clifd, const app_pkt_t *pkt)
{
	bundle *b;
	char *buf;
	int pid, wid, leader_pid;

	b = bundle_decode(pkt->data, pkt->len);
	bundle_get_str(b, AUL_K_PID, &buf);
	pid = atoi(buf);
	bundle_get_str(b, AUL_K_WID, &buf);
	wid = atoi(buf);
	bundle_get_str(b, AUL_K_LEADER_PID, &buf);
	leader_pid = atoi(buf);
	bundle_free(b);
	app_group_add(leader_pid, pid, wid);
	__real_send(clifd, 0);
}

static void __dispatch_app_group_remove(int clifd, const app_pkt_t *pkt)
{
	bundle *b;
	char *buf;
	int pid;

	b = bundle_decode(pkt->data, pkt->len);
	bundle_get_str(b, AUL_K_PID, &buf);
	pid = atoi(buf);
	bundle_free(b);
	app_group_remove(pid);
	__real_send(clifd, 0);
}

static void __dispatch_app_group_get_window(int clifd, const app_pkt_t *pkt)
{
	bundle *b;
	char *buf;
	int pid;
	int wid;

	b = bundle_decode(pkt->data, pkt->len);
	bundle_get_str(b, AUL_K_PID, &buf);
	pid = atoi(buf);
	bundle_free(b);
	wid = app_group_get_window(pid);
	__real_send(clifd, wid);
}

static void __dispatch_app_group_resume(int clifd, int pid)
{
	app_group_resume(pid);
	__real_send(clifd, 0);
}

static void __dispatch_app_group_get_leader_pid(int clifd,
		const app_pkt_t *pkt)
{
	bundle *b;
	char *buf;
	int pid;
	int lpid;

	b = bundle_decode(pkt->data, pkt->len);
	bundle_get_str(b, AUL_K_PID, &buf);
	pid = atoi(buf);
	bundle_free(b);
	lpid = app_group_get_leader_pid(pid);
	__real_send(clifd, lpid);
}

static void __dispatch_app_group_get_leader_pids(int clifd,
		const app_pkt_t *pkt)
{
	int cnt;
	int *pids;
	int empty[1] = { 0 };

	app_group_get_leader_pids(&cnt, &pids);

	if (pids == NULL || cnt == 0) {
		__send_result_data(clifd, APP_GROUP_GET_LEADER_PIDS,
				(unsigned char *)empty, 0);
	} else {
		__send_result_data(clifd, APP_GROUP_GET_LEADER_PIDS,
				(unsigned char *)pids, cnt * sizeof(int));
	}
	if (pids != NULL)
		free(pids);
}

static void __dispatch_app_group_get_group_pids(int clifd, const app_pkt_t *pkt)
{
	bundle *b;
	char *buf;
	int leader_pid;
	int cnt;
	int *pids;
	int empty[1] = { 0 };

	b = bundle_decode(pkt->data, pkt->len);
	bundle_get_str(b, AUL_K_LEADER_PID, &buf);
	leader_pid = atoi(buf);
	bundle_free(b);

	app_group_get_group_pids(leader_pid, &cnt, &pids);
	if (pids == NULL || cnt == 0) {
		__send_result_data(clifd, APP_GROUP_GET_GROUP_PIDS,
				(unsigned char *)empty, 0);
	} else {
		__send_result_data(clifd, APP_GROUP_GET_GROUP_PIDS,
				(unsigned char *)pids, cnt * sizeof(int));
	}
	if (pids != NULL)
		free(pids);
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
	char *appid;
	char *term_pid;
	int pid;
	bundle *kb = NULL;
	item_pkt_t *item;
	struct appinfo *ai;

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
				if (item == NULL) {
					_E("out of memory");
					return FALSE;
				}
				item->pid = ret;
				item->uid = cr.uid;
				strncpy(item->appid, appid, 511);

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
		case APP_PAUSE:
			kb = bundle_decode(pkt->data, pkt->len);
			appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);
			ret = _status_app_is_running_v2(appid, cr.uid);
			if (ret > 0) {
				ret = _pause_app(ret, clifd);
			} else {
				_E("%s is not running", appid);
				close(clifd);
			}
			break;
		case APP_RESUME_BY_PID:
		case APP_PAUSE_BY_PID:
		case APP_TERM_REQ_BY_PID:
			kb = bundle_decode(pkt->data, pkt->len);
			appid = (char *)bundle_get_val(kb, AUL_K_APPID);
			ret = __app_process_by_pid(pkt->cmd, appid, &cr, clifd);
			break;
		case APP_TERM_BY_PID_WITHOUT_RESTART:
		case APP_TERM_BY_PID_ASYNC:
			/* TODO: check caller's privilege */
			kb = bundle_decode(pkt->data, pkt->len);
			term_pid = (char *)bundle_get_val(kb, AUL_K_APPID);
			appid = _status_app_get_appid_bypid(atoi(term_pid));
			ai = appinfo_find(cr.uid, appid);
			if (ai) {
				appinfo_set_value(ai, AIT_STATUS, "norestart");
				ret = __app_process_by_pid(pkt->cmd, term_pid, &cr, clifd);
			} else {
				ret = -1;
				close(clifd);
			}
			break;
		case APP_TERM_BY_PID:
		case APP_KILL_BY_PID:
			/* TODO: check caller's privilege */
			kb = bundle_decode(pkt->data, pkt->len);
			appid = (char *)bundle_get_val(kb, AUL_K_APPID);
			ret = __app_process_by_pid(pkt->cmd, appid, &cr, clifd);
			break;
		case APP_TERM_BGAPP_BY_PID:
			/* TODO: check caller's privilege */
			kb = bundle_decode(pkt->data, pkt->len);
			appid = (char *)bundle_get_val(kb, AUL_K_APPID);
			ret = __app_process_by_pid(pkt->cmd, appid, &cr, clifd);
			break;
		case APP_RUNNING_INFO:
			_status_send_running_appinfo(clifd, cr.uid);
			break;
		case APP_IS_RUNNING:
			appid = malloc(MAX_PACKAGE_STR_SIZE);
			if (appid == NULL) {
				_E("out of memory");
				__send_result_to_client(clifd, -1);
				break;
			}
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
			if (appid == NULL) {
				_E("out of memory");
				__send_result_to_client(clifd, -1);
				break;
			}
			strncpy(appid, (const char*)pkt->data, MAX_PACKAGE_STR_SIZE-1);
			ret = __release_srv(cr.uid, appid);
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
		case AMD_RELOAD_APPINFO:
			_D("AMD_RELOAD_APPINFO");
			appinfo_reload();
			__send_result_to_client(clifd, 0);
			break;

		case APP_GROUP_ADD:
			__dispatch_app_group_add(clifd, pkt);
			break;

		case APP_GROUP_REMOVE:
			__dispatch_app_group_remove(clifd, pkt);
			break;

		case APP_GROUP_GET_WINDOW:
			__dispatch_app_group_get_window(clifd, pkt);
			break;

		case APP_GROUP_GET_LEADER_PIDS:
			__dispatch_app_group_get_leader_pids(clifd, pkt);
			break;

		case APP_GROUP_GET_GROUP_PIDS:
			__dispatch_app_group_get_group_pids(clifd, pkt);
			break;

		case APP_GROUP_RESUME:
			__dispatch_app_group_resume(clifd, cr.pid);
			break;

		case APP_GROUP_GET_LEADER_PID:
			__dispatch_app_group_get_leader_pid(clifd, pkt);
			break;
		default:
			_E("no support packet");
			close(clifd);
	}

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

int _requset_init(void)
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

	return 0;
}


