/*
 *  aul
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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

#ifndef __APP_COM_H__
#define __APP_COM_H__

#include <bundle.h>

typedef enum {
	AUL_APP_COM_PUBLIC = 0x0, /* allowed for all */
	AUL_APP_COM_PRIVILEGED = 0x1, /* allowed for given privileged app */
} aul_app_com_propagate_option_e;

typedef enum {
	AUL_APP_COM_R_ERROR_OK = 0,
	AUL_APP_COM_R_ERROR_UNKNOWN_ENDPOINT = -1,
	AUL_APP_COM_R_ERROR_ENDPOINT_ALREADY_EXISTS = -2,
	AUL_APP_COM_R_ERROR_ILLEGAL_ACCESS = -3,
	AUL_APP_COM_R_ERROR_CLIENT_REMAINING = -4,
	AUL_APP_COM_R_ERROR_FATAL_ERROR = -5,
} aul_app_com_error_e;

typedef enum {
	AUL_APP_COM_R_OK = 0,
	AUL_APP_COM_R_ILLEGAL_ACCESS = -1,
} aul_app_com_result_e;

typedef struct _aul_app_com_permission_t {
	char *privilege;
	unsigned int propagation;
} aul_app_com_permission_t;

typedef int (*app_com_receiver)(const char *endpoint, aul_app_com_result_e result, bundle *envelope, void *user_data);

/**
 * aul_app_com provides publish-subscribe style message for internal AUL use.
 * e.g) widget status propagation, sharing callee app status to caller app
 */

/*
 * @brief	Creates endpoint for communication
 * @param[in]	endpoint	an address for communication. e.g) aul.status, widget.status
 * @param[in]	permission	permission info
 */
int aul_app_com_create(const char *endpoint, aul_app_com_permission_t *permission, app_com_receiver handler, void *user_data);
int aul_app_com_permission_set_propagation(aul_app_com_permission_t *permission, aul_app_com_propagate_option_e option);
int aul_app_com_permission_set_privilege(aul_app_com_permission_t *permission, const char *privilege);
int aul_app_com_join(const char *endpoint, const char *filter, app_com_receiver handler, void *user_data);
int aul_app_com_send(const char *endpoint, bundle *envelope);
int aul_app_com_leave(const char *endpoint, app_com_receiver handler, void *user_data);

int app_com_recv(bundle *b);

#endif
