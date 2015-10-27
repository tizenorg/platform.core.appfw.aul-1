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
#include <cynara-client.h>
#include <cynara-creds-socket.h>
#include <cynara-session.h>
#include <systemd/sd-login.h>

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
#define REGULAR_UID_MIN     5000

#define PRIVILEGE_APPMANAGER_LAUNCH "http://tizen.org/privilege/appmanager.launch"
#define PRIVILEGE_APPMANAGER_KILL "http://tizen.org/privilege/appmanager.kill"
#define PRIVILEGE_APPMANAGER_KILL_BGAPP "http://tizen.org/privilege/appmanager.kill.bgapp"

#define MAX_NR_OF_DESCRIPTORS 2
static GHashTable *__socket_pair_hash = NULL;

typedef int (*app_cmd_dispatch_func)(int clifd, const app_pkt_t *pkt, struct ucred *cr);

static cynara *r_cynara = NULL;

static int __send_result_to_client(int fd, int res);
static gboolean __request_handler(gpointer data);

int __send_message(int sock, const struct iovec *vec, int vec_size, const int *desc, int nr_desc)
{
	struct msghdr msg = {0};
	int sndret;

	if (vec == NULL || vec_size < 1)
		return -EINVAL;
	if (nr_desc < 0 || nr_desc > MAX_NR_OF_DESCRIPTORS)
		return -EINVAL;
	if (desc == NULL)
		nr_desc = 0;

	msg.msg_iov = (struct iovec *)vec;
	msg.msg_iovlen = vec_size;

	/* sending ancillary data */
	if (nr_desc > 0) {
		int desclen = 0;
		struct cmsghdr *cmsg = NULL;
		char buff[CMSG_SPACE(sizeof(int) * MAX_NR_OF_DESCRIPTORS)] = {0};

		msg.msg_control = buff;
		msg.msg_controllen = sizeof(buff);
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL)
			return -EINVAL;

		/* packing files descriptors */
		if (nr_desc > 0) {
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			desclen = cmsg->cmsg_len = CMSG_LEN(sizeof(int) * nr_desc);
			memcpy((int *)CMSG_DATA(cmsg), desc, sizeof(int) * nr_desc);
			cmsg = CMSG_NXTHDR(&msg, cmsg);

			_D("packing file descriptors done");
		}

		/* finished packing updating the corect length */
		msg.msg_controllen = desclen;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	sndret = sendmsg(sock, &msg, 0);

	_D("sendmsg ret : %d", sndret);
	if(sndret < 0) return -errno;
	else return sndret;
}

static int __send_result_data(int fd, int cmd, unsigned char *kb_data, int datalen)
{
	int len;
	int sent = 0;
	int res = 0;
	app_pkt_t *pkt = NULL;

	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + datalen);
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
		ret = _term_req_app(pid, clifd);
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

static void __handle_agent_dead_signal(struct ucred *pcr)
{
	/* TODO: check the credentials from the caller: must be the amd agent */

	_D("AGENT_DEAD_SIGNAL : %d", pcr->uid);
	__agent_dead_handler(pcr->uid);
}

gboolean __dispatch_get_socket_pair(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{

	char *caller;
	char *callee;
	char *socket_pair_key;
	int socket_pair_key_len;
	int *handles;
	struct iovec vec[3];
	int msglen;
	char buffer[1024];
	struct sockaddr_un saddr;
	char *datacontrol_type;
	bundle *kb;

	kb = bundle_decode(pkt->data, pkt->len);
	caller = (char *)bundle_get_val(kb, AUL_K_CALLER_APPID);
	callee = (char *)bundle_get_val(kb, AUL_K_CALLEE_APPID);
	datacontrol_type = (char *)bundle_get_val(kb, "DATA_CONTOL_TYPE");

	socket_pair_key_len = strlen(caller) + strlen(callee) + 2;

	socket_pair_key = (char *)calloc(socket_pair_key_len, sizeof(char));

	if (socket_pair_key == NULL) {
		_E("calloc fail");
		goto err_out;
	}

	snprintf(socket_pair_key, socket_pair_key_len, "%s_%s", caller, callee);
	_E("socket pair key : %s", socket_pair_key);

	handles = g_hash_table_lookup(__socket_pair_hash, socket_pair_key);

	if (handles == NULL) {

		handles = (int *)calloc(2, sizeof(int));
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, handles) != 0) {
			_E("error create socket pair");
			__send_result_to_client(clifd, -1);
			goto err_out;
		}

		if(handles[0] == -1) {
			_E("error socket open");
			__send_result_to_client(clifd, -1);
			goto err_out;
		}
		g_hash_table_insert(__socket_pair_hash, strdup(socket_pair_key),
				handles);

		_E("New socket pair insert done.");
	}


	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;

	SECURE_LOGD("amd send fd : [%d, %d]", handles[0], handles[1]);
	vec[0].iov_base = buffer;
	vec[0].iov_len = strlen(buffer) + 1;

	if (datacontrol_type != NULL) {
		_E("datacontrol_type : %s", datacontrol_type);
		if (strcmp(datacontrol_type, "consumer") == 0) {

			msglen = __send_message(clifd, vec, 1, &handles[0], 1);
			if(msglen < 0) {
				_E("Error[%d]: while sending message\n", -msglen);
				__send_result_to_client(clifd, -1);
				goto err_out;
			}
			close(handles[0]);
			handles[0] = -1;
			if (handles[1] == -1) {
				_E("remove from hash : %s", socket_pair_key);
				g_hash_table_remove(__socket_pair_hash, socket_pair_key);
			}

		}
		else {
			msglen = __send_message(clifd, vec, 1, &handles[1], 1);
			if(msglen < 0) {
				_E("Error[%d]: while sending message\n", -msglen);
				__send_result_to_client(clifd, -1);
				goto err_out;
			}
			close(handles[1]);
			handles[1] = -1;
			if (handles[0] == -1) {
				_E("remove from hash : %s", socket_pair_key);
				g_hash_table_remove(__socket_pair_hash, socket_pair_key);
			}
		}
	}
	SECURE_LOGD("send_message msglen : [%d]\n", msglen);

	return TRUE;

err_out:
	if (handles)
		free(handles);
	if (socket_pair_key)
		free(socket_pair_key);

	return FALSE;
}

static int __dispatch_app_group_add(int clifd, const app_pkt_t *pkt, struct ucred *cr)
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

	return 0;
}

static int __dispatch_app_group_remove(int clifd, const app_pkt_t *pkt, struct ucred *cr)
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

	return 0;
}

static int __dispatch_app_group_get_window(int clifd, const app_pkt_t *pkt, struct ucred *cr)
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

	return 0;
}

static int __dispatch_app_group_resume(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	app_group_resume(cr->pid);
	__real_send(clifd, 0);

	return 0;
}

static int __dispatch_app_group_get_leader_pid(int clifd, const app_pkt_t *pkt, struct ucred *cr)
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

	return 0;
}

static int __dispatch_app_group_get_leader_pids(int clifd, const app_pkt_t *pkt, struct ucred *cr)
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

	return 0;
}

static int __dispatch_app_group_get_group_pids(int clifd, const app_pkt_t *pkt, struct ucred *cr)
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

	return 0;
}

static int __dispatch_app_start(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	const char *appid;
	const char *target_uid;
	bundle *kb;
	int ret = -1;
	int t_uid;
	char *state;
	item_pkt_t *item;

	kb = bundle_decode(pkt->data, pkt->len);
	if (kb == NULL) {
		close(clifd);
		return -1;
	}

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (cr->uid < REGULAR_UID_MIN) {
		target_uid = bundle_get_val(kb, AUL_K_TARGET_UID);
		if (target_uid != NULL) {
			t_uid = atoi(target_uid);
			sd_uid_get_state(t_uid, &state);
			if (strcmp(state, "offline") &&
			    strcmp(state, "closing")) {
				ret = _start_app(appid, kb, pkt->cmd, cr->pid,
						t_uid, clifd);
			} else {
				_E("uid:%d session is %s", t_uid, state);
				__real_send(clifd, AUL_R_ERROR);
				return -1;
			}
		} else {
			_E("request from root, treat as global user");
			ret = _start_app(appid, kb, pkt->cmd, cr->pid,
					GLOBAL_USER, clifd);
		}
	} else {
		ret = _start_app(appid, kb, pkt->cmd, cr->pid, cr->uid, clifd);
	}
	if (ret > 0) {
		item = calloc(1, sizeof(item_pkt_t));
		if (item == NULL) {
			_E("out of memory");
			return -1;
		}
		item->pid = ret;
		item->uid = cr->uid;
		strncpy(item->appid, appid, 511);

		g_timeout_add(1200, __add_item_running_list, item);
	}
	bundle_free(kb);

	return 0;
}

static int __dispatch_app_result(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	bundle *kb;

	kb = bundle_decode(pkt->data, pkt->len);
	if (kb == NULL) {
		close(clifd);
		return -1;
	}

	__foward_cmd(pkt->cmd, kb, cr->pid);
	close(clifd);
	bundle_free(kb);

	return 0;
}

static int __dispatch_app_pause(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	char *appid;
	bundle *kb;
	int ret;

	kb = bundle_decode(pkt->data, pkt->len);
	if (kb == NULL) {
		close(clifd);
		return -1;
	}

	appid = (char *)bundle_get_val(kb, AUL_K_PKG_NAME);
	ret = _status_app_is_running_v2(appid, cr->uid);
	if (ret > 0) {
		ret = _pause_app(ret, clifd);
	} else {
		_E("%s is not running", appid);
		close(clifd);
	}
	bundle_free(kb);

	return 0;
}

static int __dispatch_app_process_by_pid(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	char *appid;
	bundle *kb;

	kb = bundle_decode(pkt->data, pkt->len);
	if (kb == NULL) {
		close(clifd);
		return -1;
	}

	appid = (char *)bundle_get_val(kb, AUL_K_APPID);
	__app_process_by_pid(pkt->cmd, appid, cr, clifd);
	bundle_free(kb);

	return 0;
}

static int __dispatch_app_term_async(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	char *appid;
	bundle *kb;
	char *term_pid;
	struct appinfo *ai;

	kb = bundle_decode(pkt->data, pkt->len);
	if (kb == NULL) {
		close(clifd);
		return -1;
	}

	term_pid = (char *)bundle_get_val(kb, AUL_K_APPID);
	appid = _status_app_get_appid_bypid(atoi(term_pid));
	ai = appinfo_find(cr->uid, appid);
	if (ai) {
		appinfo_set_value(ai, AIT_STATUS, "norestart");
		__app_process_by_pid(pkt->cmd, term_pid, cr, clifd);
	} else {
		close(clifd);
	}
	bundle_free(kb);

	return 0;
}

static int __dispatch_app_term(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	char *appid;
	bundle *kb;

	kb = bundle_decode(pkt->data, pkt->len);
	if (kb == NULL) {
		close(clifd);
		return -1;
	}

	appid = (char *)bundle_get_val(kb, AUL_K_APPID);
	__app_process_by_pid(pkt->cmd, appid, cr, clifd);
	bundle_free(kb);

	return 0;
}

static int __dispatch_app_running_info(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	_status_send_running_appinfo(clifd, cr->uid);
	return 0;
}

static int __dispatch_app_is_running(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	char *appid = NULL;
	int ret;

	appid = malloc(MAX_PACKAGE_STR_SIZE);
	if (appid == NULL) {
		_E("out of memory");
		__send_result_to_client(clifd, -1);
		return -1;
	}
	strncpy(appid, (const char*)pkt->data, MAX_PACKAGE_STR_SIZE-1);
	ret = _status_app_is_running(appid, cr->uid);
	SECURE_LOGD("APP_IS_RUNNING : %s : %d",appid, ret);
	__send_result_to_client(clifd, ret);
	free(appid);

	return 0;
}

static int __dispatch_app_get_appid_by_pid(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	int pid;
	int ret;

	memcpy(&pid, pkt->data, pkt->len);
	ret = _status_get_appid_bypid(clifd, pid);
	_D("app_get_appid_bypid : %d : %d", pid, ret);
	return 0;
}

static int __dispatch_app_get_pkgid_by_pid(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	int pid;
	int ret;

	memcpy(&pid, pkt->data, sizeof(int));
	ret = _status_get_pkgid_bypid(clifd, pid);
	_D("APP_GET_PKGID_BYPID : %d : %d", pid, ret);
	return 0;
}

static int __dispatch_legacy_command(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	__send_result_to_client(clifd, 0);
	return 0;
}

static int __dispatch_app_status_update(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	int *status;
	char *appid;
	struct appinfo *ai;

	status = (int *)pkt->data;
	if (*status == STATUS_NORESTART) {
		appid = _status_app_get_appid_bypid(cr->pid);
		ai = appinfo_find(cr->uid, appid);
		appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "norestart");
	} else {
		_status_update_app_info_list(cr->pid, *status, cr->uid);
	}
	close(clifd);

	return 0;
}

static int __dispatch_app_get_status(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	int pid;
	int ret;

	memcpy(&pid, pkt->data, sizeof(int));
	ret = _status_get_app_info_status(pid, 0);
	__send_result_to_client(clifd, ret);

	return 0;
}

static int __dispatch_app_released(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	char *appid;
	int ret;

	appid = malloc(MAX_PACKAGE_STR_SIZE);
	if (appid == NULL) {
		_E("out of memory");
		__send_result_to_client(clifd, -1);
		return -1;
	}
	strncpy(appid, (const char*)pkt->data, MAX_PACKAGE_STR_SIZE-1);
	ret = __release_srv(cr->uid, appid);
	__send_result_to_client(clifd, ret);
	free(appid);

	return 0;
}

static int __dispatch_agent_dead_signal(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	_D("AMD_AGENT_DEAD_SIGNAL");
	__handle_agent_dead_signal(cr);
	close(clifd);

	return 0;
}

static int __dispatch_amd_reload_appinfo(int clifd, const app_pkt_t *pkt, struct ucred *cr)
{
	_D("AMD_RELOAD_APPINFO");
	appinfo_reload();
	__send_result_to_client(clifd, 0);

	return 0;
}

static int __get_caller_info_from_cynara(int sockfd, char **client, char **user, char **session)
{
	pid_t pid;
	int r;
	char buf[MAX_LOCAL_BUFSZ] = {0,};

	r = cynara_creds_socket_get_pid(sockfd, &pid);
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_creds_socket_get_pid failed: %s", buf);
		return -1;
	}

	*session = cynara_session_from_pid(pid);
	if (*session == NULL) {
		_E("cynara_session_from_pid failed.");
		return -1;
	}

	r = cynara_creds_socket_get_user(sockfd, USER_METHOD_DEFAULT, user);
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_cred_socket_get_user failed.");
		return -1;
	}

	r = cynara_creds_socket_get_client(sockfd, CLIENT_METHOD_DEFAULT, client);
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_creds_socket_get_client failed.");
		return -1;
	}

	return 0;
}

static const char *__convert_cmd_to_privilege(int cmd)
{
	switch (cmd) {
	case APP_OPEN:
	case APP_RESUME:
	case APP_START:
	case APP_START_RES:
		return PRIVILEGE_APPMANAGER_LAUNCH;
	case APP_TERM_BY_PID_WITHOUT_RESTART:
	case APP_TERM_BY_PID_ASYNC:
	case APP_TERM_BY_PID:
	case APP_KILL_BY_PID:
		return PRIVILEGE_APPMANAGER_KILL;
	case APP_TERM_BGAPP_BY_PID:
		return PRIVILEGE_APPMANAGER_KILL_BGAPP;
	default:
		return NULL;
	}
}

static int __check_privilege_by_cynara(int sockfd, const char *privilege)
{
	int r;
	int ret;
	char buf[MAX_LOCAL_BUFSZ] = {0,};
	char *client = NULL;
	char *session = NULL;
	char *user = NULL;

	r = __get_caller_info_from_cynara(sockfd, &client, &user, &session);
	if (r < 0) {
		ret = -1;
		goto end;
	}

	r = cynara_check(r_cynara, client, session, user, privilege);
	switch (r) {
	case CYNARA_API_ACCESS_ALLOWED:
		_D("%s(%s) from user %s privilege %s allowed.", client, session, user, privilege);
		ret = 0;
		break;
	case CYNARA_API_ACCESS_DENIED:
		_E("%s(%s) from user %s privilege %s denied.", client, session, user, privilege);
		ret = -1;
		break;
	default:
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_check failed: %s", buf);
		ret = -1;
		break;
	}

end:
	free(user);
	free(session);
	free(client);

	return ret;
}

static app_cmd_dispatch_func dispatch_table[APP_CMD_MAX] = {
	[APP_GET_SOCKET_PAIR] =  __dispatch_get_socket_pair,
	[APP_START] =  __dispatch_app_start,
	[APP_OPEN] = __dispatch_app_start,
	[APP_RESUME] = __dispatch_app_start,
	[APP_RESUME_BY_PID] = __dispatch_app_process_by_pid,
	[APP_TERM_BY_PID] = __dispatch_app_term,
	[APP_TERM_BY_PID_WITHOUT_RESTART] = __dispatch_app_term_async,
	[APP_RESULT] = __dispatch_app_result,
	[APP_START_RES] = __dispatch_app_start,
	[APP_CANCEL] = __dispatch_app_result,
	[APP_KILL_BY_PID] = __dispatch_app_term,
	[APP_ADD_HISTORY] = NULL,
	[APP_RUNNING_INFO] = __dispatch_app_running_info,
	[APP_RUNNING_INFO_RESULT] = NULL,
	[APP_IS_RUNNING] = __dispatch_app_is_running,
	[APP_GET_APPID_BYPID] = __dispatch_app_get_appid_by_pid,
	[APP_GET_PKGID_BYPID] = __dispatch_app_get_pkgid_by_pid,
	[APP_GET_INFO_OK] = NULL,
	[APP_GET_INFO_ERROR] = NULL,
	[APP_KEY_EVENT] = NULL,
	[APP_KEY_RESERVE] = __dispatch_legacy_command,
	[APP_KEY_RELEASE] = __dispatch_legacy_command,
	[APP_STATUS_UPDATE] = __dispatch_app_status_update,
	[APP_RELEASED] = __dispatch_app_released,
	[APP_RUNNING_LIST_UPDATE] = __dispatch_legacy_command,
	[APP_TERM_REQ_BY_PID] = __dispatch_app_process_by_pid,
	[APP_TERM_BY_PID_ASYNC] = __dispatch_app_term_async,
	[APP_TERM_BGAPP_BY_PID] = __dispatch_app_term,
	[APP_PAUSE] = __dispatch_app_pause,
	[APP_PAUSE_BY_PID] = __dispatch_app_process_by_pid,
	[APP_GROUP_ADD] = __dispatch_app_group_add,
	[APP_GROUP_REMOVE] = __dispatch_app_group_remove,
	[APP_GROUP_GET_WINDOW] = __dispatch_app_group_get_window,
	[APP_GROUP_GET_LEADER_PIDS] = __dispatch_app_group_get_leader_pids,
	[APP_GROUP_GET_GROUP_PIDS] = __dispatch_app_group_get_group_pids,
	[APP_GROUP_RESUME] = __dispatch_app_group_resume,
	[APP_GROUP_GET_LEADER_PID] = __dispatch_app_group_get_leader_pid,
	[APP_GET_STATUS] = __dispatch_app_get_status,
	[AMD_RELOAD_APPINFO] = __dispatch_amd_reload_appinfo,
	[AGENT_DEAD_SIGNAL] = __dispatch_agent_dead_signal,
};

static gboolean __request_handler(gpointer data)
{
	GPollFD *gpollfd = (GPollFD *) data;
	int fd = gpollfd->fd;
	app_pkt_t *pkt;
	int ret;
	int clifd;
	struct ucred cr;
	const char *privilege;

	if ((pkt = __app_recv_raw(fd, &clifd, &cr)) == NULL) {
		_E("recv error");
		return FALSE;
	}

	if (cr.uid >= REGULAR_UID_MIN) {
		privilege = __convert_cmd_to_privilege(pkt->cmd);
		if (privilege) {
			ret = __check_privilege_by_cynara(clifd, privilege);
			if (ret < 0) {
				_E("request has been denied by smack");
				ret = -EILLEGALACCESS;
				__real_send(clifd, ret);
				free(pkt);
				return TRUE;
			}
		}
	}

	if (pkt->cmd >= 0 && pkt->cmd < APP_CMD_MAX && dispatch_table[pkt->cmd]) {
		if (dispatch_table[pkt->cmd](clifd, pkt, &cr) != 0)
			_E("callback returns FALSE : %d", pkt->cmd);
	} else {
		_E("Invalid packet or not supported command");
		close(clifd);
	}
	free(pkt);

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

int _request_init(void)
{
	int fd;
	int r;
	GPollFD *gpollfd;
	GSource *src;

	__socket_pair_hash = g_hash_table_new_full(g_str_hash,  g_str_equal, NULL, g_free);

	fd = __create_sock_activation();
	if (fd == -1) {
		_D("Create server socket without socket activation");
		fd = __create_server_sock(AUL_UTIL_PID);
		if (fd == -1) {
			_E("Create server socket failed.");
			return -1;
		}
	}

	r = cynara_initialize(&r_cynara, NULL);
	if (r != CYNARA_API_SUCCESS) {
		_E("cynara initialize failed.");
		close(fd);
		return -1;
	}

	src = g_source_new(&funcs, sizeof(GSource));
	if (!src) {
		_E("out of memory");
		cynara_finish(r_cynara);
		close(fd);
		return -1;
	}

	gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
	if (!gpollfd) {
		_E("out of memory");
		g_source_destroy(src);
		cynara_finish(r_cynara);
		close(fd);
		return -1;
	}

	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc) __request_handler,
			(gpointer) gpollfd, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);

	r = g_source_attach(src, NULL);
	if (r  == 0) {
		g_free(gpollfd);
		g_source_destroy(src);
		cynara_finish(r_cynara);
		close(fd);
		return -1;
	}

	return 0;
}
