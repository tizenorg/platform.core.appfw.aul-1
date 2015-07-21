#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <aul.h>
#include <pkgmgr-info.h>

#include "app_sock.h"
#include "simple_util.h"
#include "amd_launch.h"
#include "amd_app_group.h"

#define APP_SVC_K_LAUNCH_MODE   "__APP_SVC_LAUNCH_MODE__"

static GHashTable *app_group_hash = NULL;
static int dead_pid = -1;
static int focused_leader_pid = -1;

typedef struct _app_group_context_t {
	int pid;
	int wid;
	int status;
} app_group_context_t;

static gint __comp_pid(gconstpointer a, gconstpointer b)
{
	app_group_context_t *ac1 = (app_group_context_t*) a;

	return ac1->pid - (int)b;
}

static void __list_destroy_cb(gpointer data)
{
	free(data);
}

static gboolean __hash_table_cb(gpointer key, gpointer value,
		gpointer user_data)
{
	int pid = (int) user_data;
	GList *list = (GList*) value;
	GList *itr = g_list_first(list);

	while (itr != NULL) {
		app_group_context_t *ac = (app_group_context_t*) itr->data;

		if (ac->pid == pid) {
			free(ac);
			list = g_list_remove_link(list, itr);
			if (g_list_length(list) == 0) {
				g_list_free_full(list, __list_destroy_cb);
				return TRUE;
			} else
				return FALSE;
		}
		itr = g_list_next(itr);
	}

	return FALSE;
}

static gboolean __is_top(int pid)
{
	int cnt;
	int *pids = NULL;
	int i;
	gboolean found = FALSE;

	app_group_get_leader_pids(&cnt, &pids);
	for (i = 0; i < cnt; i++) {
		int *gpids = NULL;
		int gcnt;

		app_group_get_group_pids(pids[i], &gcnt, &gpids);
		if (gcnt > 0 && gpids[gcnt - 1] == pid)
			found = TRUE;

		if (gpids != NULL)
			free(gpids);

		if (found)
			break;
	}

	if (pids != NULL)
		free(pids);

	_D("is top: %d", found);
	return found;
}

static GList* __find_removable_apps(int from)
{
	int cnt;
	int *pids = NULL;
	GList *list = NULL;
	gboolean found = FALSE;
	int i, j;

	app_group_get_leader_pids(&cnt, &pids);

	for (i = 0; i < cnt; i++) {
		int *gpids = NULL;
		int gcnt;

		app_group_get_group_pids(pids[i], &gcnt, &gpids);
		for (j = 0; j < gcnt; j++) {
			if (gpids[j] == from) {
				found = TRUE;
				continue;
			}

			if (found) {
				list = g_list_append(list, (gpointer) gpids[j]);
			}
		}

		if (gpids != NULL)
			free(gpids);

		if (found)
			break;
	}

	if (pids != NULL)
		free(pids);

	return list;
}

void app_group_init(void)
{
	app_group_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
			NULL);
}

void app_group_add(int leader_pid, int pid, int wid)
{
	app_group_context_t *ac = malloc(sizeof(app_group_context_t));
	if (ac == NULL) {
		_E("out of memory");
		return;
	}

	ac->pid = pid;
	ac->wid = wid;
	dead_pid = -1;

	GList *list = (GList*) g_hash_table_lookup(app_group_hash,
			GINT_TO_POINTER(leader_pid));
	if (list != NULL) {
		if (g_list_find_custom(list, (gconstpointer)pid, __comp_pid) != NULL) {
			_E("pid exist");
			free(ac);
			return;
		}
	}
	list = g_list_append(list, ac);
	g_hash_table_insert(app_group_hash, GINT_TO_POINTER(leader_pid), list);
}

void app_group_remove(int pid)
{
	g_hash_table_foreach_remove(app_group_hash, __hash_table_cb,
			GINT_TO_POINTER(pid));
}

int app_group_get_window(int pid)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		GList *list = (GList*) value;
		GList *i = g_list_first(list);

		while (i != NULL) {
			app_group_context_t *ac = (app_group_context_t*) i->data;

			if (ac->pid == pid) {
				return ac->wid;
			}
			i = g_list_next(i);
		}
	}

	return -1;
}

void app_group_clear_top(int pid)
{
	if (!__is_top(pid)) {
		GList *list = __find_removable_apps(pid);

		if (list != NULL) {
			GList *itr = g_list_last(list);

			while (itr != NULL) {
				int p = (int)(itr->data);

				aul_app_group_detach_window(p);
				_term_sub_app(p);
				app_group_remove(p);
				itr = g_list_previous(itr);
			}
			g_list_free(list);
		}
	}
}

void app_group_resume(int pid)
{
	app_group_clear_top(pid);
}

gboolean app_group_is_group_app(bundle* kb, uid_t uid)
{
	if (kb == NULL)
		return FALSE;

	char *str = NULL;
	char *mode = NULL;
	char *appid = NULL;
	int ret;

	pkgmgrinfo_appinfo_h handle;

	bundle_get_str(kb, AUL_K_APPID, &appid);

	if (appid == NULL)
		return FALSE;

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, uid, &handle);
	if (ret != PMINFO_R_OK)
		return FALSE;
	ret = pkgmgrinfo_appinfo_get_launch_mode(handle, &mode);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return FALSE;
	}

	if (mode != NULL && strncmp(mode, "caller", 6) == 0) {
		bundle_get_str(kb, APP_SVC_K_LAUNCH_MODE, &str);

		if (str != NULL && strncmp(str, "group", 5) == 0) {
			pkgmgrinfo_appinfo_destroy_appinfo(handle);
			return TRUE;
		}
	} else if (mode != NULL && strncmp(mode, "group", 5) == 0) {
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return TRUE;
	}

	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return FALSE;
}

void app_group_get_leader_pids(int *cnt, int **pids)
{
	GHashTableIter iter;
	gpointer key, value;

	int size = g_hash_table_size(app_group_hash);
	int *leader_pids;

	if (size > 0) {
		leader_pids = (int*) malloc(sizeof(int) * size);
		if (leader_pids == NULL) {
			_E("out of memory");
			*cnt = 0;
			*pids = NULL;
			return;
		}

		g_hash_table_iter_init(&iter, app_group_hash);
		int i = 0;
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			leader_pids[i] = (int) key;
			i++;
		}

		*cnt = size;
		*pids = leader_pids;
	} else {
		*cnt = 0;
		*pids = NULL;
	}
}

gboolean app_group_is_leader_pid(int pid)
{
	int cnt;
	int *pids = NULL;
	int i;

	app_group_get_leader_pids(&cnt, &pids);

	for (i=0; i<cnt; i++) {
		if (pid == pids[i]) {
			free(pids);
			return TRUE;
		}
	}

	if (pids != NULL)
		free(pids);

	return FALSE;
}

void app_group_get_group_pids(int leader_pid, int *cnt, int **pids)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		if ((int) key == leader_pid) {
			GList *list = (GList*) value;
			GList *i = g_list_first(list);
			int size = g_list_length(list);

			if (size > 0) {
				int *pid_array = (int*) malloc(sizeof(int) * size);
				int j = 0;

				if (pid_array == NULL) {
					_E("out of memory");
					*cnt = 0;
					*pids = NULL;
					return;
				}

				while (i != NULL) {
					app_group_context_t *ac = (app_group_context_t*) i->data;

					pid_array[j] = ac->pid;
					i = g_list_next(i);
					j++;
				}

				*cnt = size;
				*pids = pid_array;
			} else {
				*cnt = 0;
				*pids = NULL;
			}
			return;
		}
	}

	*cnt = 0;
	*pids = NULL;
}

gboolean app_group_is_sub_app(int pid)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		GList *list = (GList*) value;
		GList *found = NULL;

		if (list != NULL) {
			if ((found = g_list_find_custom(list, (gconstpointer)pid, __comp_pid)) != NULL) {
				if (g_list_first(list) == found)
					return FALSE;
				return TRUE;
			}
		}
	}

	return FALSE;
}

void app_group_reroute(int pid)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		GList *list = (GList*) value;
		GList *found = NULL;
		GList *before = NULL;
		GList *after = NULL;

		if (list != NULL) {
			if ((found = g_list_find_custom(list, (gconstpointer)pid, __comp_pid)) != NULL) {
				before = g_list_previous(found);
				after = g_list_next(found);

				if (before == NULL || after == NULL)
					return;

				_D("reroute");
				app_group_context_t *ac1 = (app_group_context_t*) before->data;
				app_group_context_t *ac2 = (app_group_context_t*) after->data;

				aul_app_group_detach_window(ac2->wid);
				aul_app_group_attach_window(ac1->wid, ac2->wid);
				break;
			}
		}
	}
}

int app_group_get_leader_pid(int pid)
{
	GHashTableIter iter;
	gpointer key, value;
	int lpid = -1;
	int again = 0;

repeat:
	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		GList *list = (GList*) value;

		if (list != NULL) {
			if (g_list_find_custom(list, (gconstpointer)pid, __comp_pid) != NULL) {
				lpid = (int)key;
				break;
			}
		}
	}

	if (lpid == -1 && dead_pid == pid)
		lpid = focused_leader_pid;

	if (lpid == -1 && again == 0) {
		pid = getpgid(pid);
		again = 1;
		goto repeat;
	}

	return lpid;
}

void app_group_set_dead_pid(int pid)
{
	focused_leader_pid = app_group_get_leader_pid(pid);
	dead_pid = pid;

	if (dead_pid == focused_leader_pid) {
	   focused_leader_pid = -1;
	   dead_pid = -1;
	}
}

int app_group_get_status(int pid)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		GList *list = (GList*) value;
		GList *i = g_list_first(list);

		while (i != NULL) {
			app_group_context_t *ac = (app_group_context_t*) i->data;

			if (ac->pid == pid)
				return  ac->status;

			i = g_list_next(i);
		}
	}
	return -1;
}

int app_group_set_status(int pid, int status)
{
        GHashTableIter iter;
        gpointer key, value;

        g_hash_table_iter_init(&iter, app_group_hash);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
                GList *list = (GList*) value;
                GList *i = g_list_first(list);

                while (i != NULL) {
                        app_group_context_t *ac = (app_group_context_t*) i->data;

                        if (ac->pid == pid) {
                                ac->status = status;
				return 0;
			}
                        i = g_list_next(i);
                }
        }
	return -1;

}
