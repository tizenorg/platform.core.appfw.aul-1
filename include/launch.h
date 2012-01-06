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


#ifndef __APP_LAUNCH_H_
#define __APP_LAUNCH_H_

int aul_initialize();
int aul_register_init_callback(
	int (*aul_handler)(aul_type type, bundle *, void *), void *data);
int aul_is_initialized();
int aul_sock_handler(int fd);
int aul_make_bundle_from_argv(int argc, char **argv, bundle **kb);

int app_start(bundle *kb);
int app_send_cmd(int pid, int cmd, bundle *kb);
int app_request_to_launchpad(int cmd, const char *pkgname, bundle *kb);

#endif
