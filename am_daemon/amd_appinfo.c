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
};

struct appinfo {
	char *val[_AI_MAX];
};

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

pkgmgrinfo_pkginfo_h p_handle;

static int __svc_app_info_insert_handler (const pkgmgrinfo_appinfo_h handle, void *data)
{
	struct appinfo *c;
	struct appinfomgr *cf = (struct appinfomgr *)data;
	gboolean r;
	char *exec;
	char *type;
	bool onboot;
	bool restart;
	char *appid;

	pkgmgrinfo_appinfo_get_appid(handle, &appid);

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

	c->val[_AI_COMP] = strdup("svc"); //TODO :

	r = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	c->val[_AI_EXEC] = strdup(exec);

	r = pkgmgrinfo_pkginfo_get_type(p_handle, &type);
	c->val[_AI_TYPE] = strdup(type);

	r = pkgmgrinfo_appinfo_is_onboot(handle, &onboot);
	if(onboot == true)
		c->val[_AI_ONBOOT] = strdup("true");
	else c->val[_AI_ONBOOT] = strdup("false");

	r = pkgmgrinfo_appinfo_is_autorestart(handle, &restart);
	if(restart == true)
		c->val[_AI_RESTART] = strdup("true");
	else c->val[_AI_RESTART] = strdup("false");

	_D("%s : %s : %s : %s : %s", c->val[_AI_FILE], c->val[_AI_COMP], c->val[_AI_TYPE], c->val[_AI_ONBOOT], c->val[_AI_RESTART]);

	g_hash_table_insert(cf->tbl, c->val[_AI_FILE], c);

	return 0;
}

static int __ui_app_info_insert_handler (const pkgmgrinfo_appinfo_h handle, void *data)
{
	struct appinfo *c;
	struct appinfomgr *cf = (struct appinfomgr *)data;
	gboolean r;
	char *exec;
	char *type;
	bool multiple;
	char *appid;

	pkgmgrinfo_appinfo_get_appid(handle, &appid);

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

	c->val[_AI_COMP] = strdup("ui"); //TODO :

	r = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	c->val[_AI_EXEC] = strdup(exec);

	r = pkgmgrinfo_pkginfo_get_type(p_handle, &type);
	c->val[_AI_TYPE] = strdup(type);

	r = pkgmgrinfo_appinfo_is_multiple(handle, &multiple);
	if(multiple == true)
		c->val[_AI_MULTI] = strdup("true");
	else c->val[_AI_MULTI] = strdup("false");

	_D("%s : %s : %s : %s", c->val[_AI_FILE], c->val[_AI_COMP], c->val[_AI_TYPE], c->val[_AI_MULTI]);

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

static int __pkg_info_handler(const pkgmgrinfo_pkginfo_h handle, void *data)
{
	int r;

	p_handle = handle;
	r = pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, __svc_app_info_insert_handler, data);
	r = pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __ui_app_info_insert_handler, data);

	return 0;
}

static int _read_pkg_info(struct appinfomgr *cf)
{
	int r;

	r = pkgmgrinfo_pkginfo_get_list(__pkg_info_handler, cf);

	return 0;
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
	char *pkgname;
	pkgmgrinfo_appinfo_h handle;
	pkgmgrinfo_app_component component;
	struct appinfomgr *cf = (struct appinfomgr *)data;

	noti_string = vconf_keynode_get_str(key);
	if( noti_string == NULL ) {
		return;
	}

	_D("noti_string : %s",noti_string);

	type_string = strtok_r(noti_string, ":", &saveptr);
	appid = strtok_r(NULL, ":", &saveptr);

	if ( strncmp(type_string, "create", 6) == 0) {
		pkgmgrinfo_appinfo_get_appinfo(appid, &handle);

		_D("appid : %s /handle : %x", appid, handle);
		pkgmgrinfo_appinfo_get_component(handle, &component);

		pkgmgrinfo_appinfo_get_pkgname(handle, &pkgname);
		pkgmgrinfo_pkginfo_get_pkginfo(pkgname, &pkgname);

		_D("pkgname : %s /handle : %x", pkgname, pkgname);

		if(component == PMINFO_UI_APP) {
			__ui_app_info_insert_handler(handle, data);
		} else if (component == PMINFO_SVC_APP) {
			__svc_app_info_insert_handler(handle, data);
		}

		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		pkgmgrinfo_pkginfo_destroy_pkginfo(p_handle);
	} else if ( strncmp(type_string, "delete", 6) == 0) {
		g_hash_table_remove(cf->tbl, appid);
	}
}

int appinfo_init(struct appinfomgr **cf)
{
	struct appinfomgr *_cf;
	int r;

	if (!cf) {
		errno = EINVAL;
		_E("appinfo init: %s", strerror(errno));
		return -1;
	}

	_cf = _init();
	if (!_cf)
		return -1;

	r = _read_pkg_info(_cf);
	if (r == -1) {
		_fini(_cf);
		return -1;
	}

	r = vconf_notify_key_changed("memory/menuscreen/desktop", __vconf_cb, _cf);

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
	int r;
	pkgmgrinfo_pkginfo_h handle;

	r = pkgmgrinfo_pkginfo_get_pkginfo(pkg_name, &handle);
	p_handle = handle;
	r = pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, __svc_app_info_insert_handler, cf);
	r = pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __ui_app_info_insert_handler, cf);
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return cf;
}

void appinfo_delete(struct appinfomgr *cf, const char *pkg_name)
{
	int r;
	pkgmgrinfo_pkginfo_h handle;

	r = pkgmgrinfo_pkginfo_get_pkginfo(pkg_name, &handle);
	r = pkgmgrinfo_appinfo_get_list(handle, PMINFO_SVC_APP, __app_info_delete_handler, cf);
	r = pkgmgrinfo_appinfo_get_list(handle, PMINFO_UI_APP, __app_info_delete_handler, cf);
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

