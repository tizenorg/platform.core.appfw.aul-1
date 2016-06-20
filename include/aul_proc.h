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

#include <unistd.h>
#include <ctype.h>

/*
 * This API is only for Appfw internally.
 */
int aul_proc_iter_appid(int (*iterfunc)(const char *dname, const char *appid,
			void *priv, uid_t uid), void *priv);

/*
 * This API is only for Appfw internally.
 */
char *aul_proc_get_appid_bypid(int pid);

/*
 * This API is only for Appfw internally.
 */
uid_t aul_proc_get_usr_bypid(int pid);

/*
 * This API is only for Appfw internally.
 */
char *aul_proc_get_cmdline_bypid(int pid);
