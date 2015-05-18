#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <dirent.h>

#include <package-manager.h>
#include <pkgmgr-info.h>
#include <vconf.h>
#include "amd_config.h"
#include "simple_util.h"
#include "amd_appinfo.h"


#define SERVICE_GROUP "Service"

static pkgmgr_client *pc;
static GList *appinfo_list;
static GHashTable *pkg_pending;
struct user_appinfo {
	uid_t uid;
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
	_AI_PRELOAD,
	_AI_STATUS,
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
	[_AI_PRELOAD] = { "Preload", AIT_PRELOAD, },
	[_AI_STATUS] = { "Status", AIT_STATUS, },
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

static int __app_info_insert_handler (const pkgmgrinfo_appinfo_h handle, void *data)
{
	struct appinfo *c;
	gboolean r;
	struct user_appinfo *info = (struct user_appinfo *)data;
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
	bool preload;

	if (!handle) {
		_E("null app handle");
		return -1;
	}
	ret = pkgmgrinfo_appinfo_get_appid(handle, &appid);
	if (ret < 0) {
		_E("fail to get appinfo");
		return -1;
	}

	g_hash_table_remove(info->tbl, appid);

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

		r = pkgmgrinfo_appinfo_is_preload(handle, &preload);
		if (preload == false) {
			c->val[_AI_PRELOAD] = strdup("false");
		} else {
			c->val[_AI_PRELOAD] = strdup("true");
		}

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

	c->val[_AI_STATUS] = strdup("installed");

	SECURE_LOGD("%s : %s : %s", c->val[_AI_FILE], c->val[_AI_COMP], c->val[_AI_TYPE]);

	g_hash_table_insert(info->tbl, c->val[_AI_FILE], c);

	return 0;
}

static int __app_info_delete_handler(const pkgmgrinfo_appinfo_h handle, void *data)
{
	struct user_appinfo *info = (struct user_appinfo *)data;
	char *appid;

	if (pkgmgrinfo_appinfo_get_appid(handle, &appid))
		return -1;

	g_hash_table_remove(info->tbl, appid);

	return 0;
}

static int __pkg_list_cb(pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	bool is_global;
	struct user_appinfo *info = (struct user_appinfo *)user_data;

	if (pkgmgrinfo_pkginfo_is_for_all_users(handle, &is_global)) {
		_E("get pkginfo failed");
		return -1;
	}

	if (info->uid == GLOBAL_USER || !is_global) {
		if (pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_ALL_APP,
				__app_info_insert_handler, user_data,
				info->uid)) {
			_E("get appinfo failed");
			return -1;
		}
	}

	return 0;
}

static void _remove_user_appinfo(struct user_appinfo *info)
{
	appinfo_list = g_list_remove(appinfo_list, info);

	g_hash_table_destroy(info->tbl);
	free(info);
}

static struct user_appinfo *_add_user_appinfo(uid_t uid)
{
	int r;
	struct user_appinfo *info;
	int event_type = PMINFO_CLIENT_STATUS_UPGRADE;

	info = calloc(1, sizeof(struct user_appinfo));
	if (info == NULL) {
		_E("out of memory");
		return NULL;
	}

	info->uid = uid;
	info->tbl = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			_free_appinfo);

	appinfo_list = g_list_append(appinfo_list, info);

	r = pkgmgrinfo_pkginfo_get_usr_list(__pkg_list_cb, info, info->uid);
	if (r != PMINFO_R_OK) {
		_remove_user_appinfo(info);
		return NULL;
	}

	_D("loaded appinfo table for uid %d", uid);

	return info;
}

static struct user_appinfo *_find_user_appinfo(uid_t uid)
{
	GList *tmp;
	struct user_appinfo *info;

	for (tmp = appinfo_list; tmp; tmp = tmp->next) {
		info = (struct user_appinfo *)tmp->data;
		if (info->uid == uid)
			return info;
	}

	return NULL;
}

static void __appinfo_set_blocking_cb(void *user_data,
		const char *appid, struct appinfo *info)
{
	char *pkgid = (char *)user_data;

	if (strcmp(info->val[_AI_PKGID], pkgid))
		return;

	free(info->val[_AI_STATUS]);
	info->val[_AI_STATUS] = strdup("blocking");
	_D("%s status changed: blocking", appid);
}

static void __appinfo_unset_blocking_cb(void *user_data,
		const char *appid, struct appinfo *info)
{
	char *pkgid = (char *)user_data;

	if (strcmp(info->val[_AI_PKGID], pkgid))
		return;

	free(info->val[_AI_STATUS]);
	info->val[_AI_STATUS] = strdup("installed");
	_D("%s status changed: installed", appid);
}

static void __appinfo_remove_cb(gpointer key, gpointer value, gpointer data)
{
	char *pkgid = (char *)data;
	struct appinfo *info = (struct appinfo *)value;

	if (!strcmp(info->val[_AI_PKGID], pkgid)) {
		_D("appinfo removed: %s", info->val[_AI_NAME]);
		return TRUE;
	}

	return FALSE;
}

static void _appinfo_delete(uid_t uid, const char *pkgid)
{
	struct user_appinfo *info;

	info = _find_user_appinfo(uid);
	if (info == NULL) {
		_add_user_appinfo(uid);
		return;
	}

	g_hash_table_foreach_remove(info->tbl, __appinfo_remove_cb, pkgid);
}

static int __package_event_cb(uid_t target_uid, int req_id,
		const char *pkg_type, const char *pkgid,
		const char *key, const char *val, const void *pmsg, void *data)
{
	char *op;

	if (!strcasecmp(key, "start")) {
		if (!strcasecmp(val, "uninstall") ||
				!strcasecmp(val, "update")) {
			appinfo_foreach(target_uid, __appinfo_set_blocking_cb,
					pkgid);
		}
		g_hash_table_insert(pkg_pending, strdup(pkgid), strdup(val));
	}

	if (!strcasecmp(key, "error")) {
		if (!strcasecmp(val, "uninstall") ||
				!strcasecmp(val, "update")) {
			appinfo_foreach(target_uid, __appinfo_unset_blocking_cb,
					pkgid);
		}
		g_hash_table_remove(pkg_pending, pkgid);
	}

	if (!strcasecmp(key, "end")) {
		op = g_hash_table_lookup(pkg_pending, pkgid);
		if (op == NULL)
			return 0;

		if (!strcasecmp(op, "uninstall")) {
			_appinfo_delete(target_uid, pkgid);
		} else if (!strcasecmp(op, "install")) {
			appinfo_insert(target_uid, pkgid);
		} else if (!strcasecmp(op, "update")) {
			_appinfo_delete(target_uid, pkgid);
			appinfo_insert(target_uid, pkgid);
		}

		g_hash_table_remove(pkg_pending, pkgid);
	}

	return 0;
}

static int _init_package_event_handler(void)
{
	pc = pkgmgr_client_new(PC_LISTENING);
	if (pc == NULL)
		return -1;

	if (pkgmgr_client_listen_status(pc, __package_event_cb, NULL) < 0)
		return -1;

	return 0;
}

static _fini_package_event_handler(void)
{
	pkgmgr_client_free(pc);
}

int appinfo_init(void)
{
	int r;
	FILE *fp;
	char buf[4096] = {0,};
	char *tmp;
	struct user_appinfo *global_appinfo;

	fp = fopen("/proc/cmdline", "r");
	if (fp == NULL){
		_E("appinfo init failed: %s", strerror(errno));
		return -1;
	}
	r = fgets(buf, sizeof(buf), fp);
	tmp = strstr(buf, "gles");
	if (tmp != NULL)
		sscanf(tmp,"gles=%d", &gles);
	fclose(fp);

	pkg_pending = g_hash_table_new_full(g_str_hash, g_str_equal,
			free, free);
	if (pkg_pending == NULL)
		return -1;

	global_appinfo = _add_user_appinfo(GLOBAL_USER);
	if (global_appinfo == NULL) {
		appinfo_fini();
		return -1;
	}

	if (_init_package_event_handler()) {
		appinfo_fini();
		return -1;
	}

	return 0;
}

void appinfo_fini(void)
{
	GList *tmp;
	struct user_appinfo *info;

	g_hash_table_destroy(pkg_pending);

	for (tmp = appinfo_list; tmp; tmp = tmp->next) {
		info = (struct user_appinfo *)tmp->data;
		g_hash_table_destroy(info->tbl);
		free(info);
	}

	g_list_free(appinfo_list);

	_fini_package_event_handler();
}

int appinfo_insert(uid_t uid, const char *pkgid)
{
	struct user_appinfo *info;
	pkgmgrinfo_pkginfo_h handle;

	info = _find_user_appinfo(uid);
	if (info == NULL) {
		info = _add_user_appinfo(uid);
		if (info == NULL)
			_E("load appinfo for uid %d failed", uid);
		return 0;
	}

	if (pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle)) {
		_E("get pkginfo failed: %s", pkgid);
		return -1;
	}

	if (pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_ALL_APP,
				__app_info_insert_handler,
				info, info->uid)) {
		_E("add appinfo of pkg %s failed", pkgid);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return -1;
	}

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return 0;
}

const struct appinfo *appinfo_find(uid_t caller_uid, const char *appid)
{
	struct user_appinfo *info;

	info = _find_user_appinfo(caller_uid);
	if (info == NULL) {
		info = _add_user_appinfo(caller_uid);
		if (info == NULL)
			return NULL;
	}

	return g_hash_table_lookup(info->tbl, appid);
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
		SECURE_LOGE("appinfo get filename: %s", strerror(errno));
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

	cbi->cb(cbi->cb_data, key, value);
}

void appinfo_foreach(uid_t uid, appinfo_iter_callback cb, void *user_data)
{
	struct user_appinfo *info;
	struct _cbinfo cbi;

	info = _find_user_appinfo(uid);
	if (info == NULL) {
		info = _add_user_appinfo(uid);
		if (info == NULL)
			return;
	}

	if (!cb) {
		errno = EINVAL;
		_E("appinfo foreach: %s", strerror(errno));
		return;
	}

	cbi.cb = cb;
	cbi.cb_data = user_data;

	g_hash_table_foreach(info->tbl, _iter_cb, &cbi);
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

