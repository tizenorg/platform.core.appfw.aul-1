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

#pragma once

#include <sqlite3.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>
#include <glib.h>

#define MAX_FILTER_STR_SIZE 1024
#define MAX_PACKAGE_STR_SIZE 512
#define MAX_URI_STR_SIZE 256
#define MAX_MIME_STR_SIZE 256
#define MAX_SCHEME_STR_SIZE 256
#define MAX_HOST_STR_SIZE 256
#define MAX_OP_STR_SIZE 128

#ifdef __cplusplus
extern "C"
{
#endif

int _svc_db_check_perm(uid_t uid, bool readonly);
int _svc_db_add_app(const char *op, const char *mime_type, const char *uri, const char *pkg_name, uid_t uid);
int _svc_db_delete_with_pkgname(const char *pkg_name, uid_t uid);
char* _svc_db_get_app(const char *op, const char *mime_type, const char *uri, uid_t uid);
int _svc_db_is_defapp(const char *pkg_name, uid_t uid);
int _svc_db_adjust_list_with_submode(int mainapp_mode, char *win_id, GSList **pkg_list, uid_t uid);
int _svc_db_get_list_with_condition(char *op, char *uri, char *mime, GSList **pkg_list, uid_t uid);
int _svc_db_get_list_with_collation(char *op, char *uri, char *mime, GSList **pkg_list, uid_t uid);
int _svc_db_get_list_with_all_defapps(GSList **pkg_list, uid_t uid);
int _svc_db_delete_all(uid_t uid);



#ifdef __cplusplus
}
#endif


