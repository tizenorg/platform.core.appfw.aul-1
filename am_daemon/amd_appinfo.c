#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <glib.h>
#include <dirent.h>

#include <pkgmgr-info.h>
#include <vconf.h>
#include "amd_config.h"
#include "simple_util.h"
#include "amd_appinfo.h"


#define SERVICE_GROUP "Service"

struct appinfomgr {
	GHashTable *tbl; /* key is filename, value is struct appinfo */
};

enum _appinfo_idx {
	_AI_FILE = 0, /* service filename */
	_AI_NAME,
	_AI_COMP,
	_AI_EXEC,
	_AI_TYPE,
	_AI_ONBOOT,
	_AI_RESTART,
	_AI_MULTI,
	_AI_HWACC,
	_AI_PERM,
	_AI_PKGID,
	_AI_MAX,
};
#define _AI_START _AI_NAME /* start index */

struct appinfo_t {
	char *name;
	enum appinfo_type type;
};

static struct appinfo_t _appinfos[] = {
	[_AI_NAME] = { "Name", AIT_NAME, },
	[_AI_COMP] = { "Component", AIT_COMP, },
	[_AI_EXEC] = { "Exec", AIT_EXEC, },
	[_AI_TYPE] = { "PkgType", AIT_TYPE, },
	[_AI_ONBOOT] = { "StartOnBoot", AIT_ONBOOT, },
	[_AI_RESTART] = { "AutoRestart", AIT_RESTART, },
	[_AI_MULTI] = { "Multiple", AIT_MULTI, },
	[_AI_HWACC] = { "Hwacceleration", AIT_HWACC, },
	[_AI_PERM] = { "PermissionType", AIT_PERM, },
	[_AI_PKGID] = { "PackageId", AIT_PKGID, },
};

struct appinfo {
	char *val[_AI_MAX];
};

int gles = 1;

static void _free_appinfo(gpointer data)
{
	struct appinfo *c = data;
	int i;

	if (!c)
		return;

	for (i = 0; i < sizeof(c->val)/sizeof(c->val[0]); i++)
		free(c->val[i]);

	free(c);
}

static void _fini(struct appinfomgr *cf)
{
	assert(cf);

	g_hash_table_destroy(cf->tbl);
	free(cf);
}

static int __app_info_insert_handler (const pkgmgrinfo_appinfo_h handle, void *data)
{
	struct appinfo *c;
	struct appinfomgr *cf = (struct appinfomgr *)data;
	gboolean r;
	char *exec;
	char *type;
	char *appid;
	char *pkgid;
	bool multiple;
	bool onboot;
	bool restart;
	pkgmgrinfo_app_hwacceleration hwacc;
	pkgmgrinfo_app_component component;
	pkgmgrinfo_permission_type permission;
	int ret = -1;

	if (!handle) {
		_E("null app handle");
		return -1;
	}

	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		_E("fail to get appinfo");
		return -1;
	}

	g_hash_table_remove(cf->tbl, appid);

	c = calloc(1, sizeof(*c));
	if (!c) {
		_E("create appinfo: %s", strerror(errno));
		return -1;
	}

	memset(c, 0, sizeof(struct appinfo));

	c->val[_AI_FILE] = strdup(appid);
	if (!c->val[_AI_FILE]) {
		_E("create appinfo: %s", strerror(errno));
		_free_appinfo(c);
		return -1;
	}

	c->val[_AI_NAME] = strdup(appid); //TODO :

	pkgmgrinfo_appinfo_get_component(handle, &component);
	if(component == PMINFO_UI_APP) {
		c->val[_AI_COMP] = strdup("ui"); //TODO :

		r = pkgmgrinfo_appinfo_is_multiple(handle, &multiple);
		if(multiple == true)
			c->val[_AI_MULTI] = strdup("true");
		else c->val[_AI_MULTI] = strdup("false");

		if(gles == 0) {
			c->val[_AI_HWACC] = strdup("NOT_USE");
		} else {

			r = pkgmgrinfo_appinfo_get_hwacceleration(handle, &hwacc);
			if (hwacc == PMINFO_HWACCELERATION_USE_GL) {
				c->val[_AI_HWACC] = strdup("USE");
			} else if (hwacc == PMINFO_HWACCELERATION_USE_SYSTEM_SETTING) {
				c->val[_AI_HWACC] = strdup("SYS");
			} else {
				c->val[_AI_HWACC] = strdup("NOT_USE");
			}
		}
	} else {
		c->val[_AI_COMP] = strdup("svc");

		r = pkgmgrinfo_appinfo_is_onboot(handle, &onboot);
		if(onboot == true)
			c->val[_AI_ONBOOT] = strdup("true");
		else c->val[_AI_ONBOOT] = strdup("false");

		r = pkgmgrinfo_appinfo_is_autorestart(handle, &restart);
		if(restart == true)
			c->val[_AI_RESTART] = strdup("true");
		else c->val[_AI_RESTART] = strdup("false");
	}

	r = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	c->val[_AI_EXEC] = strdup(exec);

	r = pkgmgrinfo_appinfo_get_apptype(handle, &type);
	if(strncmp(type, "capp", 4) == 0 ) {
		c->val[_AI_TYPE] = strdup("rpm");
	} else if (strncmp(type, "c++app", 6) == 0 || strncmp(type, "ospapp", 6) == 0) {
		c->val[_AI_TYPE] = strdup("tpk");
	} else if (strncmp(type, "webapp", 6) == 0) {
		c->val[_AI_TYPE] = strdup("wgt");
	}

	r = pkgmgrinfo_appinfo_get_permission_type(handle, &permission);
	if (permission == PMINFO_PERMISSION_SIGNATURE) {
		c->val[_AI_PERM] = strdup("signature");
	} else if (permission == PMINFO_PERMISSION_PRIVILEGE) {
		c->val[_AI_PERM] = strdup("privilege");
	} else {
		c->val[_AI_PERM] = strdup("normal");
	}

	r = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	c->val[_AI_PKGID] = strdup(pkgid);

	_D("%s : %s : %s", c->val[_AI_FILE], c->val[_AI_COMP], c->val[_AI_TYPE]);

	g_hash_table_insert(cf->tbl, c->val[_AI_FILE], c);

	return 0;
}

static int __app_info_delete_handler (const pkgmgrinfo_appinfo_h handle, void *data)
{
	struct appinfomgr *cf = (struct appinfomgr *)data;
	char *appid;

	pkgmgrinfo_appinfo_get_appid(handle, &appid);

	g_hash_table_remove(cf->tbl, appid);

	return 0;
}

static int _read_pkg_info(struct appinfomgr *cf)
{
	int r;

	r = pkgmgrinfo_appinfo_get_installed_list(__app_info_insert_handler, cf);

	return r;
}

static struct appinfomgr *_init()
{
	struct appinfomgr *cf;

	cf = calloc(1, sizeof(*cf));
	if (!cf) {
		_E("appinfo init: %s", strerror(errno));
		return NULL;
	}

	cf->tbl = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, _free_appinfo);

	return cf;
}

static void __vconf_cb(keynode_t *key, void *data)
{
	char *noti_string;
	char *type_string;
	char *appid;
	char *saveptr;
	pkgmgrinfo_appinfo_h handle;
	struct appinfomgr *cf = (struct appinfomgr *)data;
	int ret;

	noti_string = vconf_keynode_get_str(key);
	if( noti_string == NULL ) {
		return;
	}

	_D("noti_string : %s",noti_string);

	type_string = strtok_r(noti_string, ":", &saveptr);
	appid = strtok_r(NULL, ":", &saveptr);

	if ( strncmp(type_string, "create", 6) == 0) {
		ret = pkgmgrinfo_appinfo_get_appinfo(appid, &handle);
		if(ret < 0) {
			_E("pkgmgrinfo_appinfo_get_appinfo fail");
		}

		_D("appid : %s /handle : %x", appid, handle);

		__app_info_insert_handler(handle, data);

		pkgmgrinfo_appinfo_destroy_appinfo(handle);
	} else if ( strncmp(type_string, "delete", 6) == 0) {
		g_hash_table_remove(cf->tbl, appid);
	} else if (strncmp(type_string, "update", 6) == 0){
		/*REMOVE EXISTING ENTRY & CREATE AGAIN*/
		if (g_hash_table_remove(cf->tbl, appid) == true){
			if (pkgmgrinfo_appinfo_get_appinfo(appid, &handle) == PMINFO_R_OK){
				__app_info_insert_handler(handle, data);
				pkgmgrinfo_appinfo_destroy_appinfo(handle);
			}
		}
	}
}

int appinfo_init(struct appinfomgr **cf)
{
	struct appinfomgr *_cf;
	int r;
	FILE *fp = NULL;
	char buf[4096] = {0,};
	char *tmp = NULL;

	if (!cf) {
		errno = EINVAL;
		_E("appinfo init: %s", strerror(errno));
		return -1;
	}

	fp = fopen("/proc/cmdline", "r");
	if (fp == NULL){
		_E("appinfo init failed: %s", strerror(errno));
		return -1;
	}
	r = fgets(buf, sizeof(buf), fp);
	tmp = strstr(buf, "gles");
	if(tmp != NULL) {
		sscanf(tmp,"gles=%d", &gles);
	}
	fclose(fp);

	_cf = _init();
	if (!_cf)
		return -1;

	r = _read_pkg_info(_cf);
	if (r != PMINFO_R_OK) {
		_fini(_cf);
		return -1;
	}

	r = vconf_notify_key_changed(VCONFKEY_MENUSCREEN_DESKTOP, __vconf_cb, _cf);
	if (r < 0)
		_E("Unable to register vconf notification callback for VCONFKEY_MENUSCREEN_DESKTOP\n");

	*cf = _cf;

	return 0;
}

void appinfo_fini(struct appinfomgr **cf)
{
	if (!cf || !*cf)
		return;

	_fini(*cf);
	*cf = NULL;
}

const struct appinfo *appinfo_insert(struct appinfomgr *cf, const char *pkg_name)
{
	pkgmgrinfo_pkginfo_h handle;
	if (pkgmgrinfo_pkginfo_get_pkginfo(pkg_name, &handle) == PMINFO_R_OK){
		pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, __app_info_insert_handler, cf);
		pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __app_info_insert_handler, cf);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	}
	return cf;
}

void appinfo_delete(struct appinfomgr *cf, const char *pkg_name)
{
	pkgmgrinfo_pkginfo_h handle;
	if (pkgmgrinfo_pkginfo_get_pkginfo(pkg_name, &handle) != PMINFO_R_OK)
		return;
	pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, __app_info_delete_handler, cf);
	pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __app_info_delete_handler, cf);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
}

const struct appinfo *appinfo_find(struct appinfomgr *cf, const char *filename)
{
	if (!cf || !filename || !*filename) {
		errno = EINVAL;
		_E("appinfo find: %s", strerror(errno));
		return NULL;
	}

	return g_hash_table_lookup(cf->tbl, FILENAME(filename));
}

const char *appinfo_get_value(const struct appinfo *c, enum appinfo_type type)
{
	enum _appinfo_idx i;

	if (!c) {
		errno = EINVAL;
		_E("appinfo get value: %s", strerror(errno));
		return NULL;
	}

	for (i = _AI_START; i < sizeof(_appinfos)/sizeof(_appinfos[0]); i++) {
		if (type == _appinfos[i].type)
			return c->val[i];
	}

	errno = ENOENT;
	_E("appinfo get value: %s", strerror(errno));

	return NULL;
}

const char *appinfo_get_filename(const struct appinfo *c)
{
	if (!c) {
		errno = EINVAL;
		_E("appinfo get filename: %s", strerror(errno));
		return NULL;
	}

	return c->val[_AI_FILE];
}

struct _cbinfo {
	appinfo_iter_callback cb;
	void *cb_data;
};

static void _iter_cb(gpointer key, gpointer value, gpointer user_data)
{
	struct _cbinfo *cbi = user_data;

	assert(cbi);

	cbi->cb(cbi->cb_data, key, value);
}

void appinfo_foreach(struct appinfomgr *cf, appinfo_iter_callback cb, void *user_data)
{
	struct _cbinfo cbi;

	if (!cf || !cb) {
		errno = EINVAL;
		_E("appinfo foreach: %s", strerror(errno));
		return;
	}

	cbi.cb = cb;
	cbi.cb_data = user_data;

	g_hash_table_foreach(cf->tbl, _iter_cb, &cbi);
}

int appinfo_get_boolean(const struct appinfo *c, enum appinfo_type type)
{
	const char *v;

	v = appinfo_get_value(c, type);
	if (!v)
		return -1;

	if (!strcmp(v, "1") || !strcasecmp(v, "true"))
		return 1;

	if (!strcmp(v, "0") || !strcasecmp(v, "false"))
		return 0;

	errno = EFAULT;

	return -1;
}

