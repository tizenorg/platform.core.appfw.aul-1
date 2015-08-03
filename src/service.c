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

#include <bundle.h>

#include "aul.h"
#include "aul_api.h"
#include "launch.h"

SLPAPI int aul_set_defapp_for_service(const char *svcname, const char *defapp)
{
	/* deprecated */
	return 0;
}

SLPAPI int aul_get_defapp_for_service(const char *svcname, char *defapp,
				      int len)
{
	/* deprecated */
	return 0;
}

SLPAPI int aul_open_service(const char *svcname, bundle *kb,
			    aul_service_res_fn cbfunc, void *userdata)
{
	/* deprecated */
	return 0;
}

SLPAPI int aul_send_service_result(bundle *b)
{
	return aul_send_result(b, 0);
}

