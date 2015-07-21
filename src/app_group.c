#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <bundle.h>

#include "aul.h"
#include "aul_api.h"
#include "aul_util.h"
#include "app_sock.h"
#include "simple_util.h"
#include "launch.h"

#ifdef WAYLAND
#include <wayland-client.h>
#include "tizen-transient-for-client-protocol.h"
static struct tizen_transient_for *tz_transient_for = NULL;

static void
_reg_handle_global(void *data, struct wl_registry *reg, uint32_t id, const char *interface, uint32_t ver)
{
   if (!strcmp(interface, "tizen_transient_for"))
     {
        tz_transient_for = wl_registry_bind(reg,
                                       id,
                                       &tizen_transient_for_interface,
                                       1);
     }
}

static void
_reg_handle_global_remove(void *data, struct wl_registry *reg, uint32_t id)
{
   // do nothing
   ;
}

static const struct wl_registry_listener reg_listener =
{
   _reg_handle_global,
   _reg_handle_global_remove
};
#endif

SLPAPI void aul_app_group_add(int leader_pid, int pid, int wid)
{
	bundle *b;
	char buf[128];

	b = bundle_create();
	snprintf(buf, 128, "%d", leader_pid);
	bundle_add_str(b, AUL_K_LEADER_PID, buf);

	snprintf(buf, 128, "%d", pid);
	bundle_add_str(b, AUL_K_PID, buf);

	snprintf(buf, 128, "%d", wid);
	bundle_add_str(b, AUL_K_WID, buf);

	app_send_cmd(AUL_UTIL_PID, APP_GROUP_ADD, b);
	bundle_free(b);
}

SLPAPI void aul_app_group_remove(int pid)
{
	bundle *b;
	char buf[128];

	b = bundle_create();
	snprintf(buf, 128, "%d", pid);
	bundle_add_str(b, AUL_K_PID, buf);

	app_send_cmd(AUL_UTIL_PID, APP_GROUP_REMOVE, b);
	bundle_free(b);
}

SLPAPI void aul_app_group_attach_window(int parent_wid, int child_wid)
{
#ifdef WAYLAND
	struct wl_display *dpy;
	struct wl_registry *reg;

	dpy = wl_display_connect(NULL);
	reg = wl_display_get_registry(dpy);
	wl_registry_add_listener(reg, &reg_listener, NULL);
	wl_display_roundtrip(dpy);

	if (!tz_transient_for)
	{
		_E("ERR: no tizen_surface_extension global interface");
		wl_registry_destroy(reg);
		wl_display_disconnect(dpy);
		return;
	}

	tizen_transient_for_set(tz_transient_for, child_wid, parent_wid);
	wl_display_roundtrip(dpy);

	tizen_transient_for_destroy(tz_transient_for);
	wl_registry_destroy(reg);
	wl_display_disconnect(dpy);
#else
	//ecore_x_icccm_transient_for_set(child_wid, parent_wid);
#endif
}

SLPAPI void aul_app_group_detach_window(int child_wid)
{
#ifdef WAYLAND
	struct wl_display *dpy;
	struct wl_registry *reg;

	dpy = wl_display_connect(NULL);
	reg = wl_display_get_registry(dpy);
	wl_registry_add_listener(reg, &reg_listener, NULL);
	wl_display_roundtrip(dpy);

	if (!tz_transient_for)
	{
		_E("ERR: no tizen_surface_extension global interface");
		wl_registry_destroy(reg);
		wl_display_disconnect(dpy);
		return;
	}

	tizen_transient_for_unset(tz_transient_for, child_wid);
	wl_display_roundtrip(dpy);

	tizen_transient_for_destroy(tz_transient_for);
	wl_registry_destroy(reg);
	wl_display_disconnect(dpy);
#else
	//ecore_x_icccm_transient_for_unset(child_wid);
#endif
}

SLPAPI int aul_app_group_get_window(int pid)
{
	int ret;
	bundle *b;
	char buf[128];

	b = bundle_create();
	snprintf(buf, 128, "%d", pid);
	bundle_add_str(b, AUL_K_PID, buf);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_GET_WINDOW, b);
	bundle_free(b);

	return ret;
}

SLPAPI void aul_app_group_get_leader_pids(int *cnt, int **pids)
{
	app_pkt_t *ret = NULL;
	*cnt = 0;
	*pids = NULL;

	ret = __app_send_cmd_with_result(AUL_UTIL_PID, APP_GROUP_GET_LEADER_PIDS,
			NULL, 0);
	if (ret != NULL) {
		*cnt = ret->len / sizeof(int);
		if (ret->len > 0 && ret->len <= INT_MAX) {
			*pids = malloc(ret->len);
			if (*pids == NULL) {
				_E("out of memory");
				free(ret);
				return;
			}

			memcpy(*pids, ret->data, ret->len);
		}
		free(ret);
	}

}

SLPAPI void aul_app_group_get_group_pids(int leader_pid, int *cnt, int **pids)
{
	app_pkt_t *ret = NULL;
	bundle *b;
	bundle_raw *br;
	int datalen;
	char buf[128];
	*cnt = 0;
	*pids = NULL;

	b = bundle_create();
	snprintf(buf, 128, "%d", leader_pid);
	bundle_add_str(b, AUL_K_LEADER_PID, buf);

	bundle_encode(b, &br, &datalen);
	ret = __app_send_cmd_with_result(AUL_UTIL_PID, APP_GROUP_GET_GROUP_PIDS, br,
			datalen);

	if (ret != NULL) {
		*cnt = ret->len / sizeof(int);
		if (ret->len > 0 && ret->len <= INT_MAX) {
			*pids = malloc(ret->len);
			if (*pids == NULL) {
				_E("out of memory");
				free(br);
				bundle_free(b);
				free(ret);
				return;
			}

			memcpy(*pids, ret->data, ret->len);
		}
		free(ret);
	}

	free(br);
	bundle_free(b);
}

SLPAPI int aul_app_group_get_leader_pid(int pid)
{
	int ret;
	bundle *b;
	char buf[128];

	b = bundle_create();
	snprintf(buf, 128, "%d", pid);
	bundle_add_str(b, AUL_K_PID, buf);
	ret = app_send_cmd(AUL_UTIL_PID, APP_GROUP_GET_LEADER_PID, b);
	bundle_free(b);

	return ret;
}

SLPAPI int aul_app_group_clear_top(void)
{
	int dummy[1] = { 0 };
	return  __app_send_raw(AUL_UTIL_PID, APP_GROUP_RESUME, (unsigned char *)dummy, 0);
}

SLPAPI int aul_app_group_is_top(void)
{
	int lpid = aul_app_group_get_leader_pid(getpid());

	if (lpid > 0) {
		int cnt;
		int *pids = NULL;
		aul_app_group_get_group_pids(lpid, &cnt, &pids);
		if (cnt > 0) {
			if (pids[cnt-1] == getpid()) {
				free(pids);
				return 1;
			}

			free(pids);
			return 0;
		}
	}

	return 1;
}
