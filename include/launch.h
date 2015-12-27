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

#include <glib.h>

int aul_initialize();
int aul_register_init_callback(
	int (*aul_handler)(aul_type type, bundle *, void *), void *data);
int aul_is_initialized();
int aul_sock_handler(int fd);
int aul_make_bundle_from_argv(int argc, char **argv, bundle **kb);

int app_start(bundle *kb);
int app_send_cmd(int pid, int cmd, bundle *kb);
int app_send_cmd_for_uid(int pid, uid_t uid, int cmd, bundle *kb);
int app_send_cmd_with_noreply(int pid, int cmd, bundle *kb);
int app_request_to_launchpad(int cmd, const char *pkgname, bundle *kb);
int app_request_to_launchpad_for_uid(int cmd, const char *pkgname, bundle *kb, uid_t uid);

int _app_start_res_prepare(bundle *kb);
int app_result(int cmd, bundle *kb, int launched_pid);
int aul_send_result(bundle *kb, int is_cancel);
int aul_launch_app_with_result(const char *pkgname, bundle *kb,
			       void (*cbfunc) (bundle *, int, void *),
			       void *data);
int app_subapp_terminate_request(void);
int __call_aul_handler(aul_type type, bundle *kb);
gboolean __aul_glib_handler(gpointer data);


