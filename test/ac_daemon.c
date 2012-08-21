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

#include <stdio.h>
#include <glib.h>
#include <stdbool.h>
#include <app-checker-server.h>
#include <rua.h>
#include <bundle.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <poll.h>
#include <ail.h>
#include <aul.h>

#include "simple_util.h"
#include "app_sock.h"
#include "aul_util.h"
#include "menu_db_util.h"

#include <Ecore_X.h>
#include <Ecore_Input.h>
#include <utilX.h>
#include <Ecore.h>
#include <Evas.h>

static struct {
	Evas_Object *win;
	Ecore_Event_Handler *key_up;
	Ecore_Event_Handler *key_down;
} key_info = {
	.win = NULL,
	.key_up = NULL,
	.key_down = NULL,
};

GSList *key_pid_list = NULL;

extern int app_send_cmd(int pid, int cmd, bundle *kb);

static gboolean __add_history_handler(gpointer user_data)
{
	struct rua_rec rec;
	int ret;
	app_pkt_t *pkt = (app_pkt_t *)user_data;
	struct history_data *hd = (struct history_data *)pkt->data;

	ret = rua_init();

	memset(&rec, 0, sizeof(rec));

	rec.pkg_name = hd->pkg_name;
	rec.app_path = hd->app_path;

	if(hd->len > 0) {
		rec.arg = (char *)hd->data;
	}

	_D("add rua history %s %s", rec.pkg_name, rec.app_path);

	ret = rua_add_history(&rec);
	if (ret == -1)
		_D("rua add history error");

	free(pkt);

	ret = rua_fini();

	return false;
}

int __send_result_to_client(int fd, int res)
{
	if (send(fd, &res, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}
	close(fd);
	return 0;
}

static int __get_pkginfo(const char *dname, const char *cmdline, void *priv)
{
	app_info_from_db *menu_info;
	char *r_info;

	r_info = (char *)priv;

	if ((menu_info = _get_app_info_from_db_by_apppath(cmdline)) == NULL)
		goto out;
	else {
		strncat(r_info, dname, 8);
		strncat(r_info, ":", 1);
		strncat(r_info, _get_pkgname(menu_info), MAX_PACKAGE_STR_SIZE);
		strncat(r_info, ":", 1);
		strncat(r_info, _get_app_path(menu_info), MAX_PACKAGE_APP_PATH_SIZE);
		strncat(r_info, ";", 1);
	}

 out:
	if (menu_info != NULL)
		_free_app_info_from_db(menu_info);
	return 0;
}

int __send_running_appinfo(int fd)
{
	app_pkt_t *pkt = NULL;
	int len;

	pkt = (app_pkt_t *) malloc(sizeof(char) * AUL_SOCK_MAXBUFF);
	if(!pkt) {
		_E("malloc fail");
		return 0;
	}

	memset(pkt, 0, AUL_SOCK_MAXBUFF);

	__proc_iter_cmdline(__get_pkginfo, pkt->data);

	pkt->cmd = APP_RUNNING_INFO_RESULT;
	pkt->len = strlen((char *)pkt->data) + 1;

	if ((len = send(fd, pkt, pkt->len + 8, 0)) != pkt->len + 8) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.\n");
		_E("send fail to client");
	}

	if(pkt)
		free(pkt);

	close(fd);
	return 0;
}

int __app_is_running(const char *pkgname)
{
	char *apppath = NULL;
	ail_appinfo_h handle;
	ail_error_e ail_ret;

	int ret = 0;
	int i = 0;

	if (pkgname == NULL)
		return 0;

	ail_ret = ail_package_get_appinfo(pkgname, &handle);
	if (ail_ret != AIL_ERROR_OK) {
		_E("ail_get_appinfo with %s failed", pkgname);
		return ret;
	}

	ail_ret = ail_appinfo_get_str(handle, AIL_PROP_EXEC_STR, &apppath);
	if (ail_ret != AIL_ERROR_OK) {
		_E("ail_appinfo_get_str failed");
		goto out;
	}

	if (apppath == NULL)
		goto out;

	/*truncate apppath if it includes default bundles */
	while (apppath[i] != 0) {
		if (apppath[i] == ' ' || apppath[i] == '\t') {
			apppath[i]='\0';
			break;
		}
		i++;
	}

	if (__proc_iter_cmdline(NULL, apppath) > 0)
		ret = 1;
	else
		ret = 0;

 out:
	if (ail_destroy_appinfo(handle) != AIL_ERROR_OK)
		_E("ail_destroy_rs failed");
	return ret;
}

static int __register_key_event(int pid)
{
	int *pid_data;
	GSList *entry;

	pid_data = malloc(sizeof(int));
	*pid_data = pid;

	key_pid_list = g_slist_prepend(key_pid_list, pid_data);

	_D("===key stack===");

	for (entry = key_pid_list; entry; entry = entry->next) {
		if (entry->data) {
			pid_data = (int *) entry->data;
			_D("pid : %d",*pid_data);
		}
	}

	return 0;
}

static int __unregister_key_event(int pid)
{
	GSList *entry;
	int *pid_data;

	for (entry = key_pid_list; entry; entry = entry->next) {
		if (entry->data) {
			pid_data = (int *) entry->data;
			if(pid == *pid_data) {
				key_pid_list = g_slist_remove(key_pid_list, entry->data);
				free(pid_data);
			}
		}
	}

	_D("===key stack===");

	for (entry = key_pid_list; entry; entry = entry->next) {
		if (entry->data) {
			pid_data = (int *) entry->data;
			_D("pid : %d",*pid_data);
		}
	}

	return 0;
}

static gboolean __util_handler(gpointer data)
{
	GPollFD *gpollfd = (GPollFD *) data;
	int fd = gpollfd->fd;
	app_pkt_t *pkt;
	int clifd;
	struct ucred cr;
	struct history_data *hd;
	int ret = -1;
	char pkgname[MAX_PACKAGE_STR_SIZE];

	if ((pkt = __app_recv_raw(fd, &clifd, &cr)) == NULL) {
		_E("recv error");
		return FALSE;
	}

	switch (pkt->cmd) {
	case APP_ADD_HISTORY:
		hd = (struct history_data *)pkt->data;
		_D("cmd : %d, pkgname : %s, app_path : %s", pkt->cmd, hd->pkg_name, hd->app_path);
		__send_result_to_client(clifd, 0);
		g_timeout_add(1000, __add_history_handler, pkt);
		break;
	case APP_RUNNING_INFO:
		__send_running_appinfo(clifd);
		free(pkt);
		break;
	case APP_IS_RUNNING:
		strncpy(pkgname, (const char*)pkt->data, MAX_PACKAGE_STR_SIZE-1);
		ret = __app_is_running(pkgname);
		__send_result_to_client(clifd, ret);
		free(pkt);
		break;
	case APP_KEY_RESERVE:
		ret = __register_key_event(cr.pid);
		__send_result_to_client(clifd, ret);
		free(pkt);
		break;
	case APP_KEY_RELEASE:
		ret = __unregister_key_event(cr.pid);
		__send_result_to_client(clifd, ret);
		free(pkt);
		break;
	default:
		_E("no support packet");
	}

	return TRUE;
}

static gboolean __au_glib_check(GSource *src)
{
	GSList *fd_list;
	GPollFD *tmp;

	fd_list = src->poll_fds;
	do {
		tmp = (GPollFD *) fd_list->data;
		if ((tmp->revents & (POLLIN | POLLPRI)))
			return TRUE;
		fd_list = fd_list->next;
	} while (fd_list);

	return FALSE;
}

static gboolean __au_glib_dispatch(GSource *src, GSourceFunc callback,
				  gpointer data)
{
	callback(data);
	return TRUE;
}

static gboolean __au_glib_prepare(GSource *src, gint *timeout)
{
	return FALSE;
}

static GSourceFuncs funcs = {
	.prepare = __au_glib_prepare,
	.check = __au_glib_check,
	.dispatch = __au_glib_dispatch,
	.finalize = NULL
};

static Eina_Bool _key_release_cb(void *data, int type, void *event)
{
	Evas_Event_Key_Up *ev = event;
	int ret;
	GSList *entry;
	int *pid_data;
	bundle *kb;

	_D("Released");

	if (!ev) {
		_D("Invalid event object");
		return ECORE_CALLBACK_RENEW;
	}

	entry = key_pid_list;
	if (entry && entry->data) {
		pid_data = (int *) entry->data;

		kb = bundle_create();
		bundle_add(kb, AUL_K_MULTI_KEY, ev->keyname);
		bundle_add(kb, AUL_K_MULTI_KEY_EVENT, AUL_V_KEY_RELEASED);

		ret = app_send_cmd(*pid_data, APP_KEY_EVENT, kb);

		bundle_free(kb);
	}

	return ECORE_CALLBACK_RENEW;
}


static Eina_Bool _key_press_cb(void *data, int type, void *event)
{
	Evas_Event_Key_Down *ev = event;
	int ret;
	GSList *entry;
	int *pid_data;
	bundle *kb;

	_D("Pressed");

	if (!ev) {
		_D("Invalid event object");
		return ECORE_CALLBACK_RENEW;
	}

	entry = key_pid_list;
	if (entry && entry->data) {
		pid_data = (int *) entry->data;

		kb = bundle_create();
		bundle_add(kb, AUL_K_MULTI_KEY, ev->keyname);
		bundle_add(kb, AUL_K_MULTI_KEY_EVENT, AUL_V_KEY_PRESSED);

		ret = app_send_cmd(*pid_data, APP_KEY_EVENT, kb);

		bundle_free(kb);
	}

	return ECORE_CALLBACK_RENEW;
}

static int __app_dead_handler(int pid, void *data)
{
	int ret;

	ret = __unregister_key_event(pid);

	return 0;
}

static void __ac_key_initailize()
{
	key_info.win = ecore_x_window_input_new(0, 0, 0, 1, 1);
	if (!key_info.win) {
		_D("Failed to create hidden window");
	}

	ecore_x_icccm_title_set(key_info.win, "acdaemon,key,receiver");
	ecore_x_netwm_name_set(key_info.win, "acdaemon,key,receiver");
	ecore_x_netwm_pid_set(key_info.win, getpid());

	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_PLAYCD, EXCLUSIVE_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_STOPCD, EXCLUSIVE_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_PAUSECD, EXCLUSIVE_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_NEXTSONG, EXCLUSIVE_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_PREVIOUSSONG, EXCLUSIVE_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_REWIND, EXCLUSIVE_GRAB);
	utilx_grab_key(ecore_x_display_get(), key_info.win, KEY_FASTFORWARD, EXCLUSIVE_GRAB);

	key_info.key_up = ecore_event_handler_add(ECORE_EVENT_KEY_UP, _key_release_cb, NULL);
	if (!key_info.key_up) {
		_D("Failed to register a key up event handler");
	}

	key_info.key_down = ecore_event_handler_add(ECORE_EVENT_KEY_DOWN, _key_press_cb, NULL);
	if (!key_info.key_down) {
		_D("Failed to register a key down event handler");
	}

	aul_listen_app_dead_signal(__app_dead_handler, NULL);
}

static int __initialize()
{
	int fd;
	int r;
	GPollFD *gpollfd;
	GSource *src;

	fd = __create_server_sock(AUL_UTIL_PID);

	src = g_source_new(&funcs, sizeof(GSource));

	gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc) __util_handler,
			      (gpointer) gpollfd, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);

	r = g_source_attach(src, NULL);
	if (r  == 0)
	{
		/* TODO: error handle*/
		return AC_R_ERROR;
	}

	__ac_key_initailize();

	return AC_R_OK;
}

int main(int argc, char *argv[])
{
	int ret;

	ecore_init();
	evas_init();
	ecore_event_init();
	ecore_x_init(NULL);

	ret = ac_server_initailize();

	ret = __initialize();

	ecore_main_loop_begin();

	return 0;
}
