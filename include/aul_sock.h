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

#define AUL_SOCK_MAXBUFF 131071
#define ELOCALLAUNCH_ID 128
#define EILLEGALACCESS 127
#define ETERMINATING 126
#define ENOLAUNCHPAD 125
#define EREJECTED 123

#define AUL_PKT_HEADER_SIZE (sizeof(int) + sizeof(int) + sizeof(int))

typedef struct _app_pkt_t {
	int cmd;
	int len;
	int opt;
	unsigned char data[1];
} app_pkt_t;

typedef enum {
	AUL_SOCK_DEFAULT = 0x0, /* default */
	AUL_SOCK_NOREPLY = 0x1, /* no reply required in app_sock_handler */
	AUL_SOCK_CLOSE = 0x2, /* close socket after sent */
	AUL_SOCK_QUEUE = 0x4, /* add request to pending list in case of receiver is busy */
} aul_sock_opt_e;

/*
 * This API is only for Appfw internally.
 */
int aul_sock_create_server(int pid, uid_t uid);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_send_raw(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen, int opt);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_send_raw_async(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen, int opt);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_send_raw_async_with_fd(int fd, int cmd, unsigned char *kb_data, int datalen, int opt);

/*
 * This API is only for Appfw internally.
 */
int aul_sock_send_raw_with_fd_reply(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen, int opt, int *ret_fd);

/*
 * This API is only for Appfw internally.
 */
app_pkt_t *aul_sock_send_raw_with_pkt_reply(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen, int opt);

/*
 * This API is only for Appfw internally.
 */
app_pkt_t *aul_sock_recv_pkt(int fd, int *clifd, struct ucred *cr);
