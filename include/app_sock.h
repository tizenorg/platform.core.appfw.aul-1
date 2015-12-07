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


#ifndef __APP_PKT_H_
#define __APP_PKT_H_

#include <unistd.h>
#define __USE_GNU
#include <sys/socket.h>
#include <linux/un.h>

enum app_cmd {
	APP_START = 0,
	APP_OPEN,
	APP_RESUME,
	APP_RESUME_BY_PID,
	APP_TERM_BY_PID,
	APP_TERM_BY_PID_WITHOUT_RESTART,
	APP_RESULT,
	APP_START_RES,
	APP_CANCEL,
	APP_KILL_BY_PID,
	APP_ADD_HISTORY,
	APP_RUNNING_INFO,
	APP_RUNNING_INFO_RESULT,
	APP_IS_RUNNING,
	APP_GET_APPID_BYPID,
	APP_GET_PKGID_BYPID,
	APP_GET_INFO_OK,
	APP_GET_INFO_ERROR,
	APP_KEY_EVENT,
	APP_KEY_RESERVE,
	APP_KEY_RELEASE,
	APP_STATUS_UPDATE,
	APP_RUNNING_LIST_UPDATE,
	APP_TERM_REQ_BY_PID,
	APP_TERM_BY_PID_ASYNC,
	APP_TERM_BGAPP_BY_PID,
	APP_PAUSE,
	APP_PAUSE_BY_PID,
	APP_GROUP_GET_WINDOW,
	APP_GROUP_SET_WINDOW,
	APP_GROUP_GET_FG,
	APP_GROUP_GET_LEADER_PID,
	APP_GROUP_GET_LEADER_PIDS,
	APP_GROUP_GET_GROUP_PIDS,
	APP_GROUP_GET_IDLE_PIDS,
	APP_GROUP_LOWER,
	APP_GROUP_CLEAR_TOP,
	APP_GET_STATUS,
	APP_GET_SOCKET_PAIR,
	APP_ADD_LOADER,
	APP_REMOVE_LOADER,

	/* for special purpose */
	AMD_RELOAD_APPINFO,
	/* reserved for AMD Agent */
	AGENT_DEAD_SIGNAL,
	APP_CMD_MAX
};

#define AUL_SOCK_PREFIX "/tmp/alaunch"
#define AUL_SOCK_MAXBUFF 65535
#define LAUNCHPAD_PID -1
#define WEB_LAUNCHPAD_PID -3
#define DEBUG_LAUNCHPAD_PID -4
#define ELOCALLAUNCH_ID 128
#define EILLEGALACCESS 127
#define ETERMINATING 126
#define ENOLAUNCHPAD 125
#define EREJECTED 123

#define PAD_CMD_LAUNCH		0
#define PAD_CMD_VISIBILITY	10
#define PAD_CMD_ADD_LOADER	11
#define PAD_CMD_REMOVE_LOADER	12

typedef struct _app_pkt_t {
	int cmd;
	int len;
	unsigned char data[1];
} app_pkt_t;
#define AUL_PKT_HEADER_SIZE (sizeof(int) + sizeof(int))

typedef struct _pkt_t {
	uid_t caller_uid;
	app_pkt_t *pkt;
} pkt_t;

int __create_server_sock(int pid);
int __create_client_sock(int pid, uid_t uid);
int __app_send_raw(int pid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_noreply(int pid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_noreply_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_delay_reply(int pid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_delay_reply_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_fd_reply(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen, int *ret_fd);
int __app_agent_send_raw(int uid, int cmd, unsigned char *kb_data, int datalen);
int __app_agent_send_raw_with_noreply(int uid, int cmd, unsigned char *kb_data, int datalen);
app_pkt_t *__app_recv_raw(int fd, int *clifd, struct ucred *cr);
app_pkt_t *__app_send_cmd_with_result(int pid, int cmd, unsigned char *kb_data, int datalen);
app_pkt_t *__app_send_cmd_with_result_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int __create_agent_client_sock(int uid);
int __create_server_sock_by_path(char *path);
int __create_sock_activation(void);
#endif

