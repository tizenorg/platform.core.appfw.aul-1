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

#ifndef __AUL_H__
#define __AUL_H__

#include <errno.h>
#include <bundle.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Return values in AUL.
 */
typedef enum _aul_return_val {
	AUL_R_EREJECTED = -14,		/**< App disable for mode */
	AUL_R_ENOAPP = -13,		/**< Failed to find app ID or pkg ID */
	AUL_R_EHIDDENFORGUEST = -11,	/**< App hidden for guest mode */
	AUL_R_ENOLAUNCHPAD = -10,	/**< no launchpad */
	AUL_R_ETERMINATING = -9,	/**< application terminating */
	AUL_R_EILLACC = -8,		/**< Illegal Access */
	AUL_R_LOCAL = -7,		/**< Launch by himself */
	AUL_R_ETIMEOUT = -6,		/**< Timeout */
	AUL_R_ECANCELED = -5,		/**< Operation canceled */
	AUL_R_EINVAL = -4,		/**< Invalid argument */
	AUL_R_ECOMM = -3,		/**< Comunication Error */
	AUL_R_ENOINIT = -2,		/**< AUL handler NOT initialized */
	AUL_R_ERROR = -1,		/**< General error */
	AUL_R_OK = 0			/**< General success */
}aul_return_val;

enum app_status {
	STATUS_LAUNCHING,
	STATUS_CREATED,
	STATUS_FOCUS,
	STATUS_VISIBLE,
	STATUS_BG,
	STATUS_DYING,
	STATUS_HOME,
	STATUS_NORESTART,
	STATUS_SERVICE
};

typedef enum _aul_type{
	AUL_START,
	AUL_RESUME,
	AUL_TERMINATE,
	AUL_TERMINATE_BGAPP,
	AUL_PAUSE,
}aul_type;

/** AUL public key - To check caller's secuirty */
#define AUL_K_CALLER_PID	"__AUL_CALLER_PID__"
/** AUL public key - To check callee's secuirty */
#define AUL_K_CALLEE_PID	"__AUL_CALLEE_PID__"
/** AUL public key - added for multiuser mode */
#define AUL_K_CALLER_UID	"__AUL_CALLER_UID__"
/** AUL public key - added for multiuser mode */
#define AUL_K_CALLEE_UID	"__AUL_CALLEE_UID__"
/** AUL public key - added for multiuser mode */
#define AUL_K_TARGET_UID	"__AUL_TARGET_UID__"
/** AUL public key - To check caller's secuirty */
#define AUL_K_CALLER_APPID	"__AUL_CALLER_APPID__"
/** AUL public key - To check caller's secuirty */
#define AUL_K_CALLEE_APPID	"__AUL_CALLEE_APPID__"
/** AUL public key - To find argv0 */
#define AUL_K_ARGV0		"__AUL_ARGV0__"
/** AUL public key - To measure launching time */
#define AUL_K_STARTTIME		"__AUL_STARTTIME__"
/** AUL public key - To support launching based on mime type */
#define AUL_K_MIME_TYPE		"__AUL_MIME_TYPE__"
/** AUL public key - To support launching based on mime type */
#define AUL_K_UNALIASED_MIME_TYPE		"__AUL_UNALIASED_MIME_TYPE__"
/** AUL public key - To support launching based on mime type */
#define AUL_K_MIME_CONTENT	"__AUL_MIME_CONTENT__"
/** AUL public key - To support launching based on service */
#define AUL_K_SERVICE_NAME		"__AUL_SERVICE_NAME__"
/** AUL public key - To force launch app selector instead of lauchingn default app */
#define AUL_K_FORCE_LAUNCH_APP_SELECTOR	"__AUL_FORCE_LAUNCH_APP_SELECTOR__"
/** AUL public key - To support debug argument */
#define AUL_K_DEBUG	"__AUL_DEBUG__"
/** AUL public key - To support SDK */
#define AUL_K_SDK	"__AUL_SDK__"
/** AUL public key - To support Media key */
#define AUL_K_MULTI_KEY	"__AUL_MULTI_KEY__"
/** AUL public key - To support Media key */
#define AUL_K_MULTI_KEY_EVENT	"__AUL_MULTI_KEY_EVENT__"
/** AUL public bundle value */
#define AUL_K_PRIVACY_APPID		"__AUL_PRIVACY_APPID__"
/** AUL public bundle value - To support Media key*/
#define AUL_V_KEY_PRESSED	"__AUL_KEY_PRESSED__"
/** AUL public bundle value - To support Media key*/
#define AUL_V_KEY_RELEASED	"__AUL_KEY_RELEASED__"
/** AUL public key - To support rua stat */
#define AUL_SVC_K_RUA_STAT_CALLER "__K_RUA_STAT_CALLER__"
#define AUL_SVC_K_RUA_STAT_TAG    "__K_RUA_STAT_TAG__"


/** AUL internal private key */
#define AUL_K_PKG_NAME		"__AUL_PKG_NAME__"
/** AUL internal private key */
#define AUL_K_WAIT_RESULT	"__AUL_WAIT_RESULT__"
/** AUL internal private key */
#define AUL_K_SEND_RESULT	"__AUL_SEND_RESULT__"
/** AUL internal private key */
#define AUL_K_TASK_MANAGE	"__AUL_TASK_MANAGE__"
/** AUL internal private key */
#define AUL_K_APP_TYPE		"__AUL_APP_TYPE__"
/** AUL internal private key - To check original caller's identity */
#define AUL_K_ORG_CALLER_PID	"__AUL_ORG_CALLER_PID__"
/** AUL internal private key - To check forwarded callee app's pid */
#define AUL_K_FWD_CALLEE_PID	"__AUL_FWD_CALLEE_PID__"
/** AUL internal private key */
#define AUL_K_NO_CANCEL        "__AUL_NO_CANCEL__"
/** AUL internal private key */
#define AUL_K_EXEC		"__AUL_EXEC__"
/** AUL internal private key */
#define AUL_K_MULTIPLE		"__AUL_MULTIPLE__"
/** AUL internal private key */
#define AUL_K_PACKAGETYPE	"__AUL_PACKAGETYPE__"
/** AUL internal private key */
#define AUL_K_HWACC		"__AUL_HWACC__"
/** AUL internal private key */
#define AUL_K_APPID		"__AUL_APPID__"
/** AUL internal private key */
#define AUL_K_PID		"__AUL_PID__"
/** AUL internal private key */
#define AUL_K_WID		"__AUL_WID__"
/** AUL internal private key */
#define AUL_K_LEADER_PID	"__AUL_LEADER_PID__"
/** AUL internal private key - To support data control */
#define AUL_K_DATA_CONTROL_TYPE   "__AUL_DATA_CONTROL_TYPE__"
/** AUL internal private key */
#define AUL_K_PKGID		"__AUL_PKGID_"

#define AUL_K_WIDGET_CLASS_ID		"__AUL_WIDGET_CLASS_ID__"

#define AUL_K_WIDGET_INSTANCE_ID	"__AUL_WIDGET_INSTANCE_ID__"

#define AUL_K_WIDGET_INSTANCE_STATUS	"__AUL_WIDGET_INSTANCE_STATUS__"

#define AUL_K_WIDGET_INTERNAL_STATUS	"__AUL_WIDGET_INTERNAL_STATUS__"

#define AUL_K_WAYLAND_DISPLAY		"__AUL_WAYLAND_DISPLAY__"

#define AUL_K_WAYLAND_WORKING_DIR	"__AUL_WAYLAND_WORKING_DIR__"

/**
 * @brief	This is callback function for aul_launch_init
 * @param[in]	type    event's type received from system
 * @param[in]	b	In case of RESET events, bundle which is received from peer
 * @param[in]	data	user-supplied data
 */
typedef int (*aul_handler_fn) (aul_type type, bundle * b, void *data);

/**
 * @par Description:
 *	This API install your AUL handler and setup AUL internal connection.
 * @par Purpose:
 *      AUL receive START(RESET), RESUME, TERMINATE events from system.\n
 *      This API use to handle the events. \n
 * @par Typical use case:
 *	In general, you need not use this API.
 *      If you use AppCore, you should NOT use this API.
 *      AppCore will set default aul_handler.
 *
 * @param[in]	handler		aul main callback handler function
 * @param[in]	data		user-supplied data for start_handler
 * @return	0 if success, negative value(<0) if fail\n
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ECANCELD	- aul handler was installed already by others
 * @retval	AUL_R_ECOMM	- error to create internal ipc
 * @retval	AUL_R_ERROR	- error to attach glib main loop
 *
 * @warning	If you use AppCore, you should NOT use this API.\n
 *		You need glib main loop.\n
 * @pre
 *	you must have aul handler to use this API.
 *	aul_luanch_init register aul handler.
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * static int aul_handler(aul_type type, bundle *kb,void *data)
 * {
 *	switch(type)
 *      {
 *	        case AUL_START:
 *			// process RESET event
 *	                break;
 *		case AUL_RESUME:
 *	                // process RESUME event
 *		        break;
 *	        case AUL_TERMINATE:
 *		        // preocess TERMINATE event
 *	                break;
 *      }
 *      return 0;
 * }
 *
 * static GMainLoop *mainloop = NULL;
 *
 * int main(int argc, char **argv)
 * {
 *      aul_launch_init(aul_handler,NULL);
 *      aul_launch_argv_handler(argc, argv);
 *
 *      mainloop = g_main_loop_new(NULL, FALSE);
 *      g_main_loop_run(mainloop);
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
*/
int aul_launch_init(aul_handler_fn handler, void *data);

/**
 * @par Description:
 *	This API create internal RESET events with given argc, argv \n
 * @par Purpose:
 *      This API's purpose is to generate reset event.
 *      If you want to generate local RESET events with argument vector format, use this API
 * @par Typical use case:
 *	In general, you need not use this API.
 *	AppCore use this API to create internal reset event.
 *
 * @param[in]	argc	# of args
 * @param[in]	argv	list of arg strings
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ENOINIT	- aul handler was NOT yet installed
 * @retval	AUL_R_ECANCLED	- error to create internal bundle with given argc,argv.
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	you must have aul handler to use this API.
 *	aul_luanch_init register aul handler.
 * @see
 *	aul_launch_init
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int send_local_reset_event()
 * {
 *	int argc=3;
 *	char* argv[4];
 *	argv[0] = "local.app";
 *	argv[1] = "event_type";
 *	argv[2] = "my_reset";
 *	argv[3] = NULL;
 *	aul_launch_argv_handler(argc,argv);
 * }
 *
 * @endcode
 * @remark
 *	If you use AppCore, you NEED NOT use this API.
 *	This API is only available in User Session.
*/
int aul_launch_argv_handler(int argc, char **argv);

/**
 * @par Description:
 *	This API creates internal RESET events with given bundle \n
 * @par Purpose:
 *  This API's purpose is to generate reset event.
 *  If you want to generate local RESET events with argument vector format, first use
 *  bundle_import_from_argv to create a bundle from the argument vector and then use this API
 *  Eventually, this API will replace aul_launch_argv_handler().
 * @par Typical use case:
 *	In general, you need not use this API.
 *	AppCore use this API to create internal reset event.
 *
 * @param[in]	b	bundle
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ENOINIT	- aul handler was NOT yet installed
 * @retval	AUL_R_ERROR	- general error
 *
 * @pre
 *	you must have aul handler to use this API.
 *	aul_luanch_init register aul handler.
 * @post
 *	None
 * @see
 *	aul_launch_init, bundle_import_from_argv
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int send_local_reset_event()
 * {
 *  bundle* b;
 *	int argc=3;
 *	char* argv[4];
 *	argv[0] = "local.app";
 *	argv[1] = "event_type";
 *	argv[2] = "my_reset";
 *	argv[3] = NULL;
 *
 *	b = bundle_import_from_argv(argc,argv);
 *	aul_launch_local(b);
 * }
 *
 * @endcode
 * @remark
 *      If you use AppCore, you NEED NOT to use this API.
 *	This API is only available in User Session.
*/
int aul_launch_local(bundle *b);

/**
 * @par Description:
 *	This API launches application with the given bundle.
 *  If the application is not running or a multiple-instance one, this API launches with the given bundle.
 *	If the application is running, this API sends a RESET event to the App.
 *	While the application is running, if the application cannot receive the RESET event,
 *	this API returns a general error(AUL_R_ERROR).\n
 * @par Purpose:
 *      This API is for caller.
 *      This API's purpose is to launch/reset application with given bundle.
 * @par Typical use case:
 *	If you know the target application's pkgname and bundle types,
 *	you can use this API to launch/reset the application.
 *
 * @param[in]	pkgname		package name to be run as callee
 * @param[in]	kb		bundle to be passed to callee
 * @return	callee's pid if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild package name
 * @retval	AUL_R_ECOM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 *
 * @see
 *	aul_open_app
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int launch_inhouse_contact_app()
 * {
 *	bundle *b;
 *	b = bundle_create();
 *	bundle_add(b,"type","SIM");
 *	aul_launch_app("org.tizen.contact",b);
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 */
int aul_launch_app(const char *appid, bundle *kb);

/**
 * @par Description:
 *	This API launches application with the given bundle.
 *  If the application is not running or a multiple-instance one, this API launches with the given bundle.
 *	If the application is running, this API sends a RESET event to the App.
 *	While the application is running, if the application cannot receive the RESET event,
 *	this API returns a general error(AUL_R_ERROR).\n
 * @par Purpose:
 *      This API is for caller.
 *      This API's purpose is to launch/reset application with given bundle.
 * @par Typical use case:
 *	If you know the target application's pkgname and bundle types,
 *	you can use this API to launch/reset the application.
 *
 * @param[in]	pkgname		package name to be run as callee
 * @param[in]	kb		bundle to be passed to callee
 * @param[in]	uid		User ID to launch
 * @return	callee's pid if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild package name
 * @retval	AUL_R_ECOM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 *
 * @see
 *	aul_open_app
 * @remark
 *	This API is also available in System Session.
 */
int aul_launch_app_for_uid(const char *appid, bundle *kb, uid_t uid);

/**
 * @par Description:
 *  This API launches application, as menu screen launches the app.
 *  Thus, if the applocation is running, this API sends a RESUME event to the app.
 *  If the application is not running, this API launches the app.
 *  While the application is running, if the application cannot receive the RESUME event,
 *  AUL tries to raise the application's default window.
 *
 * @par Purpose:
 *      This API is for caller.
 *      This API's purpose is to resume/launch application
 * @par Typical use case:
 *	If you only want to show application with previous state or default state, Use this API.
 *
 * @param[in]	pkgname		package name to be resume as callee
 * @return	callee's pid if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild package name
 * @retval	AUL_R_ECOM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 *
 * @see
 *	aul_launch_app, aul_app_is_running, aul_resume_pid
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int open_inhouse_contact_app()
 * {
 *	if(aul_app_is_running("org.tizen.contact"))
 *		aul_open_app("org.tizen.contact");
 * }
 *
 * @endcode
 * @remark
 *	If you don't want to launch the app,
 *	you should check app's running state with aul_app_is_running.
 *	This API will launch the application if the application is not running.
 *	This API is only available in User Session.
*/
int aul_open_app(const char *appid);

/**
 * @par Description:
 *	This API trigger to resume application
 * 	If the application is running, this API send a resume event to the App.
 *	If the application is not running, this API returns fail.
 *	Although the application is running, if the application cannot receive resume event,
 *	AUL try to raise the application's default windows.
 * @par Purpose:
 *      This API is for caller.
 *      This API's purpose is to send resume event.
 * @par Typical use case:
 *	If you only want to show application with previous state or default state, Use this API.
 *
 * @param[in]	pkgname		package name to be resume as callee
 * @return	callee's pid if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild package name
 * @retval	AUL_R_ECOM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 *
 * @see
 *	aul_launch_app, aul_app_is_running, aul_resume_pid
 * @deprecated
 *  This function will be deprecated. Use aul_open_add() instead.
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int resume_inhouse_contact_app()
 * {
 *	if(aul_app_is_running("org.tizen.contact"))
 *		aul_resume_app("org.tizen.contact");
 * }
 *
 * @endcode
 * @remark
 *	If you don't want to launch the app,
 *	you should check app's running state with aul_app_is_running.
 *	This API will launch the application if the application is not running.
 *	If you want to only resume without launching in multiple instance application model,
 *	you should use aul_resume_pid.
 *	This API is only available in User Session.
*/
int aul_resume_app(const char *appid);

/**
 * @par Description:
 *	This API trigger to resume application
 *	If the application is running, this API send a resume event to the App.
 *	If the application is not running, this API return AUL_R_ERROR.
 *	Although the application is running, if the application cannot receive resume event,
 *	AUL try to raise the application's default windows.
 * @par Purpose:
 *      This API is for caller.
 *      This API's purpose is to send resume event.
 * @par Typical use case:
 *	In multiple application model, If you want to only resume specific application, Use this API
 *
 * @param[in]	pid	application's pid to be resumed
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild pid
 * @retval	AUL_R_ECOM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error (include application is not running)
 * @warning	This API need to require root or inhouse permisssion \n
 *		If you have not the permission, this API return AUL_R_ERROR. \n
 * @see
 *	aul_launch_app
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int iterfunc(const aul_app_info *info, void *data)
 * {
 *	if(strcmp(info->pkg_name,"org.tizen.contact")==0)
 *		aul_resume_pid(info->pid);
 * }
 *
 * int iterate_running_apps()
 * {
 *      return aul_app_get_running_app_info(iterfunc,NULL);
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
*/
int aul_resume_pid(int pid);

/**
 * @par Description:
 *	This API trigger to terminate application
 *
 *	If the application is running, this API send a terminate event to the App. \n
 *	If the app cannot receive the event, AUL kill forcely the application.\n
 * @par Purpose:
 *      This API's purpose is to kill application
 * @par Typical use case:
 *	In general, Application like Task Manager use this API.
 *
 *		This API need to require root or inhouse permisssion. \n
 *
 * @param[in]	pid	application's pid to be terminated
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild pid
 * @retval	AUL_R_ECOM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 * @warning	This API need to require root or inhouse permisssion. \n
 *
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int iterfunc(const aul_app_info *info, void *data)
 * {
 *	if(strcmp(info->pkg_name,"org.tizen.contact")==0)
 *		aul_terminate_pid(info->pid);
 * }
 *
 * int iterate_running_apps()
 * {
 *      return aul_app_get_running_app_info(iterfunc,NULL);
 * }
 *
 * @endcode
 * @remark
 *	If you have not the permission, this API return AUL_R_ERROR. \n
 *	This API is only available in User Session.
*/
int aul_terminate_pid(int pid);

/**
 * @par Description:
 *	This API trigger to terminate application asynchronously
 *
 *	If the application is running, this API send a terminate event to the App. \n
 *	If the app cannot receive the event, AUL kill forcely the application.\n
 * @par Purpose:
 *      This API's purpose is to kill application
 * @par Typical use case:
 *	In general, Application like Task Manager use this API.
 *
 *		This API need to require root or inhouse permisssion. \n
 *
 * @param[in]	pid	application's pid to be terminated
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invaild pid
 * @retval	AUL_R_ECOM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 * @warning	This API need to require root or inhouse permisssion. \n
 * @remark
 *	If you have not the permission, this API return AUL_R_ERROR. \n
 *	This API is only available in User Session.
*/
int aul_terminate_pid_async(int pid);

/**
 *@brief Running application's information structure retrieved by AUL
 */
typedef struct _aul_app_info {
	int pid;		/**< app's pid if running*/
	char* pkg_name;		/**< application id */
	char* app_path;		/**< application excutable path */
	char* appid;
} aul_app_info;

/**
 * @brief iterator function running with aul_app_get_running_app_info
 * @param[out]	ainfo   aul_app_info retreived by aul_app_get_running_app_info
 * @param[out]	data	user-supplied data
*/
typedef int (*aul_app_info_iter_fn)(const aul_app_info *ainfo, void *data);

/**
 * @par Description:
 *	This API ask a application is running by application package name.
 * @par Purpose:
 *	To know whether some application is running or not, use this API
 * @par Typical use case:
 *	For example, If you want to know browser application running,
 *	you can check it by using this API.
 *
 * @param[in]	pkgname	application package name
 * @return	true / false
 * @retval	1	app_name is running now.
 * @retval	0	app_name is NOT running now.
 *
 * @code
 * #include <aul.h>
 *
 * int is_running_browser_app()
 * {
 *      return aul_app_is_running("org.tizen.browser");
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
*
*/
int aul_app_is_running(const char *appid);

/**
 * @par Description:
 *	This API use to get running application list.
 *	This API call iter_fn with each aul_app_info of running apps when running application is found.
 * @par Purpose:
 *	If you want to get running application list, use this API
 *	This API give you running applications which has SLP desktop file.
 * @par Typical use case:
 *	In general, this API is used by task manager appllication. (running application list viewer)
 *
 * @param[in]	iter_fn		iterator function
 * @param[in]	data		user-supplied data for iter_fn
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- internal error
 *
 * @code
 * #include <aul.h>
 *
 * int iterfunc(const aul_app_info* info, void* data)
 * {
 *	printf("\t==========================\n");
 *	printf("\t pkg_name: %s\n", info->appid);
 *	printf("\t app_path: %s\n", info->app_path);
 *	printf("\t running pid: %d\n", info->pid);
 *	printf("\t==========================\n");
 *	return 0;
 * }
 *
 * int iterate_running_apps()
 * {
 *      return aul_app_get_running_app_info(iterfunc,NULL);
 * }
 *
 * @endcode
 * @remark
 *	This API should use if you want to know running application which has desktop files.
 *	If you want to get all process list, you must iterate process information by using proc filesystem
 *	Or, If you want to get all window list, you must iterate XWindows by using XWindow APIs
 *	This API is only available in User Session.
 */
int aul_app_get_running_app_info(aul_app_info_iter_fn iter_fn, void *data);

/**
 * @par Description:
 *	This API get application package name by pid
 * @par Purpose:
 *	If you want to get package name of running application, use this API
 * @par Typical use case:
 *	In general, You can use this API when you want to know caller's information.
 *
 * @param[in]	pid		given pid
 * @param[out]	pkgname		pkgname to be get
 * @param[in]	len		length of pkgname
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- no such a package name
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * static int app_reset(bundle *b, void *data)
 * {
 *	int pid;
 * 	char appname[255];
 *
 * 	pid = atoi(bundle_get_val(b,AUL_K_CALLER_PID));
 *	aul_app_get_pkgname_bypid(pid, appname, sizeof(appname));
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
*/
int aul_app_get_pkgname_bypid(int pid, char *pkgname, int len);

/**
 * @par Description:
 *	This API get application pkgid by pid
 * @par Purpose:
 *	If you want to get pkgid of running application, use this API
 * @par Typical use case:
 *	In general, You can use this API when you want to know caller's information.
 *
 * @param[in]	pid		given pid
 * @param[out]	pkgid		package id
 * @param[in]	len		length of pkgid
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- no such a appid
 *
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * static int app_reset(bundle *b, void *data)
 * {
 *	int pid;
 * 	char pkgid[255];
 *
 * 	pid = atoi(bundle_get_val(b, AUL_K_CALLER_PID));
 *	aul_app_get_pkgid_bypid(pid, pkgid, sizeof(pkgid));
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
*/
int aul_app_get_pkgid_bypid(int pid, char *pkgid, int len);

/**
 * @par Description:
 *	This API get application pkgid by pid
 * @par Purpose:
 *	If you want to get pkgid of running application, use this API
 * @par Typical use case:
 *	In general, You can use this API when you want to know caller's information.
 *
 * @param[in]	pid		given pid
 * @param[out]	pkgid		package id
 * @param[in]	len		length of pkgid
 * @param[in]	uid		User ID
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- no such a appid
 *
 * @remark
 *	This API is also available in System Session.
*/
int aul_app_get_pkgid_bypid_for_uid(int pid, char *pkgid, int len, uid_t uid);

/**
 * @par Description:
 *	This API get application appid by pid
 * @par Purpose:
 *	If you want to get appid of running application, use this API
 * @par Typical use case:
 *	In general, You can use this API when you want to know caller's information.
 *
 * @param[in]	pid		given pid
 * @param[out]	appid		application id
 * @param[in]	len		length of pkgname
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- no such a appid
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * static int app_reset(bundle *b, void *data)
 * {
 *	int pid;
 * 	char appid[255];
 *
 * 	pid = atoi(bundle_get_val(b,AUL_K_CALLER_PID));
 *	aul_app_get_appid_bypid(pid, appid, sizeof(appid));
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
*/
int aul_app_get_appid_bypid(int pid, char *appid, int len);

/**
 * @par Description:
 *	This API get application appid by pid
 * @par Purpose:
 *	If you want to get appid of running application, use this API
 * @par Typical use case:
 *	In general, You can use this API when you want to know caller's information.
 *
 * @param[in]	pid		given pid
 * @param[out]	appid		application id
 * @param[in]	len		length of pkgname
 * @param[in]	uid		User ID
 * @return	0 if success, negative value(<0) if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- no such a appid
 * @remark
 *	This API is also available in System Session.
*/
int aul_app_get_appid_bypid_for_uid(int pid, char *appid, int len, uid_t uid);

/**
 * @par Description:
 *	This API launch application associated with given filename
 * @par Purpose:
 *      This API is for caller.
 *	This API launch application based on mime type.
 *	This API find mime_type associated with file name,
 *	and then find default app associated with found mime_type
 *	and then launch the app with filename argument.
 * @par Typical use case:
 *	You can launch application to process given filename.
 *	That is, Even if you don't know the specific application's pkgname,
 *	you can launch the applicaiton processing given filename .
 *	For example, If you want to process image file, you can simply launch image viewer.
 *	At that time, you can use this APIs like aul_open_file("myimage.jpg");
 *
 * @param[in]	filename	filename
 * @return	callee's pid or 0 if success, negative value if fail\n
 *              (when no found default app, return 0)
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(filename)
 * @retval	AUL_R_ECOM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 *
 * @code
 * #include <aul.h>
 *
 * int view_image_file(char *filename)
 * {
 *      aul_open_file(filename);
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 *
 */
int aul_open_file(const char* filename);

/**
 * @par Description:
 *	This API launch application associated with given specific mimetype
 * @par Purpose:
 *      This API is for caller.
 *	This API launch application based on mime type like aul_open_file API.
 *	But, This API don't find mime_type associated with file name.
 *	This API use mimetype given by user. By using given mimetype, find default application.
 *	and then launch the app with filename argument.
 * @par Typical use case:
 *	Some files cannot extract exact mimetype automatically.
 *	For example, To know mime type of files with DRM lock, first we should unlock DRM file.
 *	In this case, You can use this API.
 *	First, unlock DRM file, and extract mimetype from unlock file by using aul_get_mime_from_file,
 *	and then, use this API with DRM file and extracted mime type.
 *
 * @param[in]	filename	filename
 * @param[in]	mimetype	specific mimetype
 * @return	callee's pid or 0 if success, negative value if fail\n
 *              (when no found default app, return 0)
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(filename,mimetype)
 * @retval	AUL_R_ECOM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error
 *
 * @see
 *	aul_open_file, aul_get_mime_from_file
 * @code
 * #include <aul.h>
 *
 * int view_drm_image_file(char *drm_filename)
 * {
 *	char* mimetype;
 *	// you must implement this function
 *	mimetype = get_mimetype_from_drmfile(drm_filename);
 *
 *      aul_open_file_with_mimetype(drm_filename,mimetype);
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 */
int aul_open_file_with_mimetype(const char *filename, const char *mimetype);

/**
 * @par Description:
 *	This API launch application associated with content like "http://www.samsung.com"
 * @par Purpose:
 *      This API is for caller.
 *	This API launch application based on mime type.
 *	This API find mime_type associated with content,
 *	and then find default app associated with found mime_type,
 *	and then launch the app with content argument.
 * @par Typical use case:
 *	You can launch application to process given content.
 *	That is, Even if you don't know the specific application's pkgname,
 *	you can launch the applicaiton processing given content.
 *	For example, If you want to process URL "http://www.samsung.com",
 *	you can simply launch browser.
 *	At that time, you can use this APIs like aul_open_content("http://www.samsung.com");
 *
 * @param[in]   content		content
 * @return	callee's pid or 0 if success, negative value if fail\n
 *              (when no found default app, return 0)
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(content)
 * @retval	AUL_R_ECOM	- internal AUL IPC error
 * @retval	AUL_R_ERROR	- general error or no found mimetype
 *
 * @code
 * #include <aul.h>
 *
 * int view_url(char *url)
 * {
 *      aul_open_content(url);
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 *
 */
int aul_open_content(const char* content);

/**
 * @par Description:
 *	 This API get the default application(appid) associated with MIME type
 * @par Purpose:
 *	This API use to get default application associteted with mimetype
 *	In general, Setting Application need this API.
 * @par Typical use case:
 *	Setting Application show mapping of default application / mimetype
 *
 * @param[in]	mimetype	a mime type
 * @param[out]	defapp		a application appid of the app
 * @param[in]	len		length of defapp
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(mimetype)
 * @retval	AUL_R_ERROR	- general error or no found mimetype
 *
 * @see
 *	aul_set_defapp_with_mime
 * @code
 * #include <aul.h>
 *
 * void get_text_html_defapp()
 * {
 *	char appname[255];
 *	aul_get_defapp_from_mime("text/html",appname,sizeof(appname));
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 *
 */
int aul_get_defapp_from_mime(const char *mimetype, char *defapp, int len);

/**
 * @par Description:
 *	 This API set the default application(appid) associated with MIME type
 * @par Purpose:
 *	This API use to change default application associteted with mimetype
 *	In general, Setting Application or Installer need this API.
 * @par Typical use case:
 *	Default Application associated with mimetype can be changed by Setting Application or installer
 *	So, application to process specific mimetype can be substituted.
 *
 * @param[in]	mimetype	a mime type
 * @param[in]	defapp		a application appid of the app to be set
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(mimetype)
 * @retval	AUL_R_ERROR	- general error
 *
 * @see
 *	aul_get_defapp_from_mime
 * @code
 * #include <aul.h>
 *
 * void set_text_html_defapp()
 * {
 *	aul_set_defapp_with_mime("text/html","org.tizen.browser");
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
*/
int aul_set_defapp_with_mime(const char *mimetype, const char *defapp);

/**
 * @par Description:
 *	This API get the mimetype associated with filename
 * @par Purpose:
 *	This API use to get mimetype associteted with given filename
 *	In general, This API use when you want to know only mimetype given filename.
 * @par Typical use case:
 *	For example, In trasfering data through bluetooth,
 *	additional information like mimetype should be added.
 *	In such situation, You can get mimetype by using this API.
 *
 * @param[in]	filename	file name
 * @param[out]	mimetype	a mime type
 * @param[in]	len		length of mimetype
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(filename)
 * @retval	AUL_R_ERROR	- general error
 *
 * @code
 * #include <aul.h>
 *
 * void get_mimetype()
 * {
 *	char mimetype[255];
 *	aul_get_mime_from_file("image.jpg",mimetype,sizeof(mimetype));
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 */
int aul_get_mime_from_file(const char *filename, char *mimetype, int len);

/**
 * @par Description:
 *	This API get the mimetype associated with given content
 * @par Purpose:
 *	This API use to get mimetype associteted with given content
 *	In general, This API use when you want to know only mimetype given content
 * @par Typical use case:
 *	For example, In trasfering data through bluetooth,
 *	additional information like mimetype should be added.
 *	In such situation, You can get mimetype by using this API.
 *
 * @param[in]	content		content string like "011-0000-0000"
 * @param[out]	mimetype	a mime type
 * @param[in]	len		length of mimetype
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(content)
 * @retval	AUL_R_ERROR	- general error
 *
 * @code
 * #include <aul.h>
 *
 * void get_mimetype()
 * {
 *	char mimetype[255];
 *	aul_get_mime_from_content("http://www.samsung.com",mimetype,sizeof(mimetype));
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
*/
int aul_get_mime_from_content(const char *content, char *mimetype, int len);

/**
 * @par Description:
 *	This API get the icon's name associated with given mimetype
 * @par Purpose:
 *	This API use to get icon's name associteted with given mimetype
 * @par Typical use case:
 *	If you want to show mimetype's icon, use this API.
 *
 * @param[in]	mimetype	a mime type
 * @param[out]	iconname	icon's name
 * @param[in]	len		length of iconname
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(content)
 * @retval	AUL_R_ERROR	- general error (no such mime type)
 *
 * @code
 * #include <aul.h>
 *
 * void get_mime_icon()
 * {
 *	char icon[255];
 *	aul_get_mime_icon("text/html",icon,sizeof(icon));
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 */
int aul_get_mime_icon(const char *mimetype, char *iconname, int len);

/**
 * @par Description:
 *	This API get the extensions associated with given mimetype
 * @par Purpose:
 *	This API use to get extensions associteted with given mimetype
 * @par Typical use case:
 *	In general, user is not familiar with mimetype(text/html),
 *	user is familiar with extenstions(*.html, *.htm)
 *	So, To show mimetype information to user, use this API
 *
 * @param[in]	mimetype	a mime type
 * @param[out]	extlist		extentions (ex> mpeg,mpg,mpe)
 * @param[in]	len		length of extlist
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(mimetype)
 * @retval	AUL_R_ERROR	- general error (no mimetype or no extenstion)
 *
 * @see
 *	aul_get_mime_description
 * @code
 * #include <aul.h>
 *
 * void get_extension()
 * {
 *	char extlist[255];
 *	aul_get_mime_extension("text/html",extlist,sizeof(extlist));
 * }
 *
 * @endcode
 * @remark
 *	Some mimetype don't have extension.
 *	In that case, You can use aul_get_mime_description.
 *	This API is only available in User Session.
*/
int aul_get_mime_extension(const char *mimetype, char *extlist, int len);

/**
 * @par Description:
 *	This API get the description associated with given mimetype
 * @par Purpose:
 *	This API use to get description associteted with given mimetype
 * @par Typical use case:
 *	In general, user is not familiar with mimetype(text/html),
 *	user is familiar with well-knowing information like extenstions(*.html, *.htm)
 *	But, some mimetype don't have extenstion.
 *	At that time,to show mimetype information to user, use this API
 *
 * @param[in]	mimetype	a mime type
 * @param[out]	desc		description (ex> Call client)
 * @param[in]	len		length of desc
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_EINVAL	- invalid argument(mimetype)
 * @retval	AUL_R_ERROR	- general error (no mimetype or no descrition)
 *
 * @see
 *	aul_get_mime_extension
 * @code
 * #include <aul.h>
 *
 * void get_information_from_mime()
 * {
 *	char info[255];
 *	if(aul_get_mime_extension("text/html",info,sizeof(info))<0){
 *		aul_get_mime_description("text/html",info,sizeof(info));
 *	}
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 */
int aul_get_mime_description(const char *mimetype, char *desc, int len);

/**
 * @par Description:
 *	This API create service result bundle based on bundle received in reset event.
 * @par Purpose:
 *	This API use to create result bundle to send it to caller.
 * @par Typical use case:
 *	This API is for callee which provide application service.\n
 *      To send result to caller, You must create result bundle. \n
 *      Callee(application providing the service) can send result by using this API and aul_send_service_result.
 *
 * @param[in]   inb             bundle received in reset event
 * @param[out]  outb            bundle to use for returning result
 * @return      0 if success, negative value(<0) if fail
 * @retval      AUL_R_OK        - success
 * @retval      AUL_R_EINVAL    - inb is not bundle created by aul_open_service
 * @retval      AUL_R_ERROR     - general error
 *
 * @pre
 *	To create result bundle, You need received original bundle.
 *	The original bundle can get from app_reset handler.
 * @post
 *	None
 * @see
 *	aul_send_service_result
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int app_reset(bundle *b, void *data)
 * {
 *      ad->recved_bundle = bundle_dup(b);
 * }
 *
 * int click_ok()
 * {
 *      bundle* res_bundle;
 *      aul_create_result_bundle(ad->recved_bundle,&res_bundle);
 *      bundle_add(res_bundle, "result", "1");
 *      aul_send_service_result(res_bundle);
 * }
 * @endcode
 * @remark
 *	This API is only available in User Session.
 *
 */
int aul_create_result_bundle(bundle *inb, bundle **outb);

/**
 * @par Description:
 *	This API send service result to caller with bundle
 * @par Purpose:
 *	This API is used to send result bundle to caller.
 * @par Typical use case:
 *	This API is for callee which provide application service.\n
 *      To send result to caller, You can use this API after creating result bundle. \n
 *      Callee(application to provide service) can send result by using this API and aul_create_result_bundle.
 *
 * @param[in]   b      Result data in bundle format
 * @return      0 if success, negative value(<0) if fail
 * @retval      AUL_R_OK        - success
 * @retval      AUL_R_EINVAL    - invalid result bundle
 * @retval      AUL_R_ECOMM     - internal AUL IPC error
 * @retval      AUL_R_ERROR     - general error
 *
 * @pre
 *	To send result bundle, You must create result bundle.
 *      see aul_create_result_bundle
 * @post
 *	None
 * @see
 *	aul_create_result_bundle
 * @code
 * #include <aul.h>
 * #include <bundle.h>
 *
 * int app_reset(bundle *b, void *data)
 * {
 *      ad->recved_bundle = bundle_dup(b);
 * }
 *
 * int click_ok()
 * {
 *      bundle* res_bundle;
 *      aul_create_result_bundle(ad->recved_bundle,&res_bundle);
 *      bundle_add(res_bundle, "result", "1");
 *      aul_send_service_result(res_bundle);
 * }
 * @endcode
 * @remark
 *	This API is only available in User Session.
 *
 */
int aul_send_service_result(bundle *b);

/**
 * @par Description:
 *	This API sets callback fuction that will be called when applications die.
 * @par Purpose:
 *	This API's purpose is to listen the application dead event.
 *	In general, task manager Application need this API.
 *
 * @param[in]	func		callback function
 * @param[in]	data		user data
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- general error
 *
 * @see
 *	aul_listen_app_launch_signal
 * @code
 * #include <aul.h>
 *
 * int app_dead_handler(int pid, void *data)
 * {
 * 	printf("===> %s : %d\n", __FUNCTION__, pid);
 * 	return 0;
 * }
 *
 * void dead_listen()
 * {
 *	aul_listen_app_dead_signal(app_dead_handler, NULL);
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 *
 */
int aul_listen_app_dead_signal(int (*func) (int, void *), void *data);

/**
 * @par Description:
 *	This API sets callback fuction that will be called when applications are launched.
 * @par Purpose:
 *	This API's purpose is to listen the application launching event.
 *	In general, task manager Application need this API.
 *
 * @param[in]	func		callback function
 * @param[in]	data		user data
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- general error
 *
 * @see
 *	aul_listen_app_dead_signal
 * @code
 * #include <aul.h>
 *
 * int app_launch_handler(int pid, void *data)
 * {
 * 	printf("===> %s : %d\n", __FUNCTION__, pid);
 * 	return 0;
 * }
 *
 * void dead_listen()
 * {
 *	aul_listen_app_launch_signal(app_launch_handler, NULL);
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 *
 */
int aul_listen_app_launch_signal(int (*func) (int, void *), void *data);

/**
 * @par Description:
 *	This API gets status of specified application process id.
 * @par Purpose:
 *	This API's purpose is to get the application's status.
 *
 * @param[in]	pid	pid of application
 * @return	0 or greater if success, nagative value if fail
 * @retval	STATUS_LAUNCHING
 * @retval	STATUS_CREATED
 * @retval	STATUS_FOCUS
 * @retval	STATUS_VISIBLE
 * @retval	STATUS_BG
 * @retval	STATUS_DYING
 * @retval	STATUS_HOME
 * @retval	STATUS_NORESTART
 * @see
 *	aul_status_update
 * @code
 * #include <aul.h>
 *
 * int iterfunc(const aul_app_info *info, void *data)
 * {
 *	int status;
 *	status = aul_app_get_status_bypid(info->pid);
 *	if (status == STATUS_FOCUS) {
 *		printf("%s has focus", info->app_id);
 *		(int *)data = info->pid;
 *		return -1;
 *	}
 *	return 0;
 * }
 *
 * int find_focus_app_pid()
 * {
 *	int pid = 0;
 *	aul_app_get_running_app_info(iterfunc, &pid);
 *	return pid;
 * }
 * @endcode
 * @remark
 *	This API is only available in User Session.
 */
int aul_app_get_status_bypid(int pid);

/**
 * @par Description
 * 	This API sets callback function that on application status changed.
 * @par Purpose:
 *	This API's purpose is to listen the application's status changed within
 *	the caller process. In general, a library that required to release resource on
 *	application's status may use this API.
 *
 * @param[in]	func	callback function
 * @param[in]	data	user data
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- general error
 * @see
 *	aul_remove_status_local_cb
 * @code
 * #include <aul.h>
 *
 * int status_changed(int status, void *data)
 * {
 *	if (status == STATUS_FOCUS)
 *		printf("%d has focus\n", getpid());
 *
 *	if (status == STATUS_VISIBLE)
 *		printf("%d resume\n", getpid());
 *
 *	if (status == STATUS_BG0
 *		printf("%d pause\n", getpid());
 * }
 *
 * void listen_app_status()
 * {
 *	aul_add_status_local_cb(status_changed, NULL);
 * }
 * @endcode
 * @remark
 *	This API is only available in User Session.
 *
 */
int aul_add_status_local_cb(int (*func) (int, void *), void *data);

/**
 * @par Description
 * 	This API unsets callback function that on application status changed.
 * @par Purpose:
 *	This API's purpose is to remove callback that added by
 *	aul_add_status_local_cb.
 *
 * @param[in]	func	callback function
 * @param[in]	data	user data
 * @return	0 if success, negative value if fail
 * @retval	AUL_R_OK	- success
 * @retval	AUL_R_ERROR	- general error
 *
 * @see
 *	aul_add_status_local_cb
 * @code
 * #include <aul.h>
 *
 * int status_changed(int status, void *data)
 * {
 *	if (status == STATUS_FOCUS)
 *		printf("%d has focus\n", getpid());
 *
 *	if (status == STATUS_VISIBLE)
 *		printf("%d resume\n", getpid());
 *
 *	if (status == STATUS_BG0
 *		printf("%d pause\n", getpid());
 * }
 *
 * void listen_app_status()
 * {
 *	aul_add_status_local_cb(status_changed, NULL);
 * }
 *
 * void ignore_app_status()
 * {
 *	aul_remove_status_local_cb(status_changed, NULL);
 * }
 *
 * @endcode
 * @remark
 *	This API is only available in User Session.
 *
 */
int aul_remove_status_local_cb(int (*func) (int, void *), void *data);

/*
 * This API is only for Appfw internally.
 */
int aul_terminate_bgapp_pid(int pid);

/*
 * This API is only for Appfw internally.
 */
int aul_terminate_pid_without_restart(int pid);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_external_root_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_root_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_data_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_cache_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_resource_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_tep_resource_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_shared_data_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_shared_resource_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_shared_trusted_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_external_data_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_external_cache_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_external_shared_data_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_specific_path(void);

/*
 * This API is only for Appfw internally.
 */
const char *aul_get_app_external_specific_path(void);

/*
 * This API is only for Appfw internally.
 */
int aul_get_app_shared_data_path_by_appid(const char *app_id, char **path);

/*
 * This API is only for Appfw internally.
 */
int aul_get_app_shared_resource_path_by_appid(const char *app_id, char **path);

/*
 * This API is only for Appfw internally.
 */
int aul_get_app_shared_trusted_path_by_appid(const char *app_id, char **path);

/*
 * This API is only for Appfw internally.
 */
int aul_get_app_external_shared_data_path_by_appid(const char *app_id, char **path);

/*
 * This API is only for Appfw internally.
 */
int aul_get_usr_app_shared_data_path_by_appid(const char *app_id, char **path, uid_t uid);

/*
 * This API is only for Appfw internally.
 */
int aul_get_usr_app_shared_resource_path_by_appid(const char *app_id, char **path, uid_t uid);

/*
 * This API is only for Appfw internally.
 */
int aul_get_usr_app_shared_trusted_path_by_appid(const char *app_id, char **path, uid_t uid);

/*
 * This API is only for Appfw internally.
 */
int aul_get_usr_app_external_shared_data_path_by_appid(const char *app_id, char **path, uid_t uid);

/*
 * This type is only for Appfw internally.
 */
typedef int (*subapp_fn)(void *data);

/*
 * This API is only for Appfw internally.
 */
int aul_set_subapp(subapp_fn cb, void *data);

/*
 * This API is only for Appfw internally.
 */
int aul_subapp_terminate_request_pid(int pid);

/*
 * This API is only for Appfw internally.
 */
int aul_is_subapp(void);

/*
 * This API is only for Appfw internally.
 */
int aul_kill_pid(int pid);

/*
 * This API is only for Appfw internally.
 */
int aul_add_caller_cb(int pid,  void (*caller_cb) (int, void *), void *data);

/*
 * This API is only for Appfw internally.
 */
int aul_remove_caller_cb(int pid);

/*
 * This API is only for Appfw internally.
 */
int aul_invoke_caller_cb(int pid);

/*
 * This API is only for Appfw internally.
 */
void aul_set_preinit_window(void *evas_object);

/*
 * This API is only for Appfw internally.
 */
void* aul_get_preinit_window(const char *win_name);

/*
 * This API is only for Appfw internally.
 */
void aul_set_preinit_background(void *evas_object);

/*
 * This API is only for Appfw internally.
 */
void* aul_get_preinit_background(void);

/*
 * This API is only for Appfw internally.
 */
void aul_set_preinit_conformant(void *evas_object);

/*
 * This API is only for Appfw internally.
 */
void* aul_get_preinit_conformant(void);

/*
 * This API is only for Appfw internally.
 */
void aul_set_preinit_appid(const char *appid);

/*
 * This API is only for Appfw internally.
 */
void aul_set_preinit_pkgid(const char *pkgid);

/*
 * This API is only for Appfw internally.
 */
int aul_update_freezer_status(int pid, const char* type);

/*
 * This API is only for Appfw internally.
 */
int aul_send_app_launch_request_signal(int pid, const char* appid, const char* pkgid, const char* type);

/*
 * This API is only for Appfw internally.
 */
int aul_send_app_resume_request_signal(int pid, const char* appid, const char* pkgid, const char *type);

/*
 * This API is only for Appfw internally.
 */
int aul_send_app_terminate_request_signal(int pid, const char* appid, const char* pkgid, const char *type);

/*
 * This API is only for Appfw internally.
 */
int aul_send_app_status_change_signal(int pid, const char* appid, const char* pkgid, const char* status, const char *type);

/*
 * This API is only for Appfw internally.
 */
int aul_send_app_terminated_signal(int pid);

/*
 * This API is only for Appfw internally.
 */
int aul_send_app_group_signal(int owner_pid, int child_pid, const char *child_pkgid);

/*
 * This API is only for Appfw internally.
 */
int aul_invoke_status_local_cb(int status);

/*
 * This type is only for Appfw internally.
 */
typedef int (*data_control_provider_handler_fn) (bundle *b, int request_id, void *data);

/*
 * This API is only for Appfw internally.
 */
int aul_set_data_control_provider_cb(data_control_provider_handler_fn handler);

/*
 * This API is only for Appfw internally.
 */
int aul_unset_data_control_provider_cb(void);

/*
 * This API is only for Appfw internally.
 */
int aul_pause_app(const char *appid);

/*
 * This API is only for Appfw internally.
 */
int aul_pause_pid(int pid);

/*
 * This API is only for Appfw internally.
 */
int aul_reload_appinfo(void);

/*
 * This API is only for Appfw internally.
 */
int aul_status_update(int status);

/*
 * This API is only for Appfw internally.
 */
int aul_running_list_update(char *appid, char *app_path, char *pid);

/*
 * This API is only for Appfw internally.
 */
void aul_app_group_add(int leader_pid, int pid, int wid);

/*
 * This API is only for Appfw internally.
 */
void aul_app_group_remove(int pid);

/*
 * This API is only for Appfw internally.
 */
void aul_app_group_attach_window(int parent_wid, int child_wid);

/*
 * This API is only for Appfw internally.
 */
void aul_app_group_detach_window(int child_wid);

/*
 * This API is only for Appfw internally.
 */
int aul_app_group_get_window(int pid);

/*
 * This API is only for Appfw internally.
 */
int aul_app_group_get_window(int pid);

/*
 * This API is only for Appfw internally.
 */
int aul_app_group_set_window(int wid);

/*
 * This API is only for Appfw internally.
 */
void aul_app_group_get_leader_pids(int *cnt, int **pids);

/*
 * This API is only for Appfw internally.
 */
void aul_app_group_get_group_pids(int leader_pid, int *cnt, int **pids);

/*
 * This API is only for Appfw internally.
 */
int aul_app_group_get_leader_pid(int pid);

/*
 * This API is only for Appfw internally.
 */
int aul_app_group_clear_top(void);

/*
 * This API is only for Appfw internally.
 */
int aul_app_group_is_top(void);

/*
 * This API is only for Appfw internally.
 */
int aul_app_group_get_fg_flag(int pid);

/*
 * This API is only for Appfw internally.
 */
void aul_app_group_lower(int *exit);

/*
 * This API is only for Appfw internally.
 */
void aul_app_group_get_idle_pids(int *cnt, int **pids);

/*
 * This API is only for Appfw internally.
 */
int aul_listen_widget_status(int (*aul_handler)(const char *widget_id, const char *instance_id, int status, bundle *extra, void *data), void *user_data);

/*
 * This API is only for Appfw internally.
 */
int aul_update_widget_status(const char *widget_id, const char *instance_id, int status, bundle *extra, int receiver_pid);

/*
 * This API is only for Appfw internally.
 */
int aul_request_data_control_socket_pair(bundle *b, int *fd);

/*
 * This API is only for Appfw internally.
 */
int aul_listen_booting_done_signal(int (*func) (int, void *), void *data);

/*
 * This API is only for Appfw internally.
 */
int aul_listen_cooldown_signal(int (*func) (const char *, void *), void *data);

/*
 * This API is only for Appfw internally.
 */
int aul_listen_app_status_signal(int (*func) (int, int, void *), void *data);


#ifdef __cplusplus
	}
#endif

#endif		/* __AUL_H__ */

