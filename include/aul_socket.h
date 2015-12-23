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

#pragma once

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "aul_cmd.h"

#define AUL_SOCK_MAXBUFF 65535
#define ELOCALLAUNCH_ID 128
#define EILLEGALACCESS 127
#define ETERMINATING 126
#define ENOLAUNCHPAD 125
#define EREJECTED 123

#define AUL_PKT_HEADER_SIZE (sizeof(int) + sizeof(int))

typedef struct _app_pkt_t {
	int cmd;
	int len;
	unsigned char data[1];
} app_pkt_t;

int aul_socket_create_server(int pid, uid_t uid);
int aul_socket_send_raw(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int aul_socket_send_raw_async(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int aul_socket_send_raw_with_reply(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int aul_socket_send_raw_with_fd_reply(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen, int *ret_fd);
app_pkt_t *aul_socket_send_raw_with_pkt_reply(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
app_pkt_t *aul_socket_recv_raw(int fd, int *clifd, struct ucred *cr);
