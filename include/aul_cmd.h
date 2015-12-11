/*
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

#pragma once

enum app_cmd {
	APP_START = 0,
	APP_OPEN,
	APP_RESUME,
	APP_RESUME_BY_PID,
	APP_TERM_BY_PID,
	APP_TERM_BY_PID_WITHOUT_RESTART,
	APP_RESULT,
	APP_START_RES,
	APP_CANCEL,
	APP_KILL_BY_PID,
	APP_ADD_HISTORY,
	APP_REMOVE_HISTORY,
	APP_RUNNING_INFO,
	APP_RUNNING_INFO_RESULT,
	APP_IS_RUNNING,
	APP_GET_APPID_BYPID,
	APP_GET_PKGID_BYPID,
	APP_GET_INFO_OK,
	APP_GET_INFO_ERROR,
	APP_KEY_EVENT,
	APP_KEY_RESERVE,
	APP_KEY_RELEASE,
	APP_STATUS_UPDATE,
	APP_RUNNING_LIST_UPDATE,
	APP_TERM_REQ_BY_PID,
	APP_TERM_BY_PID_ASYNC,
	APP_TERM_BGAPP_BY_PID,
	APP_PAUSE,
	APP_PAUSE_BY_PID,
	APP_GROUP_GET_WINDOW,
	APP_GROUP_SET_WINDOW,
	APP_GROUP_GET_FG,
	APP_GROUP_GET_LEADER_PID,
	APP_GROUP_GET_LEADER_PIDS,
	APP_GROUP_GET_GROUP_PIDS,
	APP_GROUP_GET_IDLE_PIDS,
	APP_GROUP_LOWER,
	APP_GROUP_CLEAR_TOP,
	APP_GET_STATUS,
	APP_GET_SOCKET_PAIR,
	APP_ADD_LOADER,
	APP_REMOVE_LOADER,
	APP_GET_PID,

	/* for special purpose */
	AMD_RELOAD_APPINFO,
	/* reserved for AMD Agent */
	AGENT_DEAD_SIGNAL,
	APP_CMD_MAX
};

