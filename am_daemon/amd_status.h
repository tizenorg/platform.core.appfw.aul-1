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

#include <unistd.h>
#include <sys/types.h>
#include <glib.h>

int _status_add_app_info_list(const char *appid, const char *app_path, int pid, int pad_pid, uid_t uid);
int _status_update_app_info_list(int pid, int status,  uid_t uid);
int _status_remove_app_info_list_with_uid(uid_t uid);
int _status_remove_app_info_list(int pid, uid_t uid);
int _status_get_app_info_status(int pid, uid_t uid);
int _status_send_running_appinfo(int fd, uid_t uid);
int _status_app_is_running(const char *appid,  uid_t uid);
int _status_app_is_running_v2(const char *appid, uid_t caller_uid);
char *_status_app_get_appid_bypid(int pid);
int _status_send_running_appinfo_v2(int fd); //depcrecated
int _status_get_appid_bypid(int fd, int pid);
int _status_get_pkgid_bypid(int fd, int pid);
int _status_init(void);


//TODO : remove

typedef struct _item_pkt_t {
	int pid;
	uid_t uid;
	char appid[512];
} item_pkt_t;

typedef struct _rua_stat_pkt_t {
	int uid;
	char *stat_tag;
	char *stat_caller;
	char appid[512];
	gboolean is_group_app;
	char *data;
	int len;
} rua_stat_pkt_t;

gboolean __add_item_running_list(gpointer user_data);



