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

#include "simple_util.h"
#include "app_sock.h"
#include "aul_util.h"
#include "menu_db_util.h"

static gboolean __add_history_handler(gpointer user_data)
{
	struct rua_rec rec;
	int ret;
	app_pkt_t *pkt = (app_pkt_t *)user_data;
	struct history_data *hd = (struct history_data *)pkt->data;

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

	pkt->cmd = RUNNING_INFO_RESULT;
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
		_E("ail_package_get_appinfo with %s failed", pkgname);
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
	if (ail_package_destroy_appinfo(handle) != AIL_ERROR_OK)
		_E("ail_destroy_rs failed");
	return ret;
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
	case ADD_HISTORY:
		hd = (struct history_data *)pkt->data;
		_D("cmd : %d, pkgname : %s, app_path : %s", pkt->cmd, hd->pkg_name, hd->app_path);
		__send_result_to_client(clifd, 0);
		g_timeout_add(1000, __add_history_handler, pkt);
		break;
	case RUNNING_INFO:
		__send_running_appinfo(clifd);
		free(pkt);
		break;
	case IS_RUNNING:
		strncpy(pkgname, (const char*)pkt->data, MAX_PACKAGE_STR_SIZE-1);
		ret = __app_is_running(pkgname);
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


int __initialize()
{
	int fd;
	int r;
	GPollFD *gpollfd;
	GSource *src;

	r = rua_init();

	if (r == -1) {
		_D("[APP %d] rua init error");
		return AC_R_ERROR;
	}

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

	return AC_R_OK;
}

int main()
{
	
	GMainLoop *mainloop;
	int ret;

	mainloop = g_main_loop_new(NULL, FALSE);

	ret = ac_server_initailize();

	ret = __initialize();

	g_main_loop_run(mainloop);

	return 0;
}
