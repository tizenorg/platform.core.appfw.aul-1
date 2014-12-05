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

#ifndef __AUL_AMD_LAUNCH_H_
#define __AUL_AMD_LAUNCH_H_

#include <bundle.h>
#include "aul_util.h"
#include "amd_appinfo.h"

int _send_to_sigkill(int pid);
int _resume_app(int pid);
int _term_app(int pid);
int _fake_launch_app(int cmd, int pid, bundle * kb);
int _start_app(char* appid, bundle* kb, int cmd, int caller_pid, uid_t caller_uid, int fd);
void service_release(const char *group);
int _start_srv(const struct appinfo *ai, bundle *kb);

int _launch_init(struct amdmgr* amd);

#endif /* __AUL_AMD_LAUNCH_H_ */
