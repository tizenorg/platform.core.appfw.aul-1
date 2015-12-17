/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#ifndef __AUL_AMD_APP_STATUS_H_
#define __AUL_AMD_APP_STATUS_H_

#include <unistd.h>
#include <sys/types.h>
#include <glib.h>
#include <stdbool.h>
#include <aul.h>

int _status_add_app_info_list(const char *appid, const char *app_path, int pid, int pad_pid, bool is_subapp, uid_t uid);
int _status_update_app_info_list(int pid, int status,  uid_t uid);
int _status_remove_app_info_list_with_uid(uid_t uid);
int _status_remove_app_info_list(int pid, uid_t uid);
int _status_get_app_info_status(int pid, uid_t uid);
int _status_send_running_appinfo(int fd, uid_t uid);
int _status_app_is_running(const char *appid,  uid_t uid);
int _status_app_is_running_v2(const char *appid, uid_t caller_uid);
void _status_find_service_apps(int pid, uid_t uid, enum app_status status, void (*send_event_to_svc_core) (int), bool suspend);
void _status_check_service_only(int pid, uid_t uid, void (*send_event_to_svc_core) (int));
char *_status_app_get_appid_bypid(int pid);
int _status_get_appid_bypid(int fd, int pid);
int _status_get_pkgid_bypid(int fd, int pid);
int _status_init(void);

#endif


