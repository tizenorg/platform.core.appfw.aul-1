#include <glib.h>
#include <stdio.h>
#include "aul.h"
#include "aul_app_com.h"

static GMainLoop *mainloop = NULL;
static int gargc;
static char **gargv;
static aul_app_com_connection_h conn = NULL;

static void __bundle_itr(const char *key, const int type, const bundle_keyval_t *kv, void *data)
{
	printf("key: %s ", key);
	printf("type: %d", type);
	printf("\n");
}

static int __handler(const char *endpoint, aul_app_com_result_e  result, bundle *envelope, void *user_data)
{
	printf("endpoint: %s (%d) received\n", endpoint, result);
	printf("---begin---\n");
	bundle_foreach(envelope, __bundle_itr, NULL);
	printf("---end---\n\n");

	return 0;
}

static void create(const char *endpoint, const char *privilege)
{
	aul_app_com_permission_h permission = NULL;

	if (privilege) {
		permission = aul_app_com_permission_create();
		aul_app_com_permission_set_privilege(permission, privilege);
		aul_app_com_permission_set_propagation(permission, AUL_APP_COM_PRIVILEGED);
	}

	aul_app_com_create(endpoint, permission, __handler, NULL, &conn);

	if (permission)
		aul_app_com_permission_destroy(permission);
}

static void join(const char *endpoint, const char *filter)
{
	int ret = aul_app_com_join(endpoint, filter, __handler, NULL, &conn);
	printf("ret: %d\n", ret);
}

static void send(const char *endpoint)
{
	int idx = 2;
	bundle *b = bundle_create();
	for (idx = 2; idx < gargc; idx += 2) {
		bundle_add_str(b, gargv[idx], gargv[idx + 1]);
	}
	int ret = aul_app_com_send(endpoint, b);
	printf("ret: %d\n", ret);

	g_main_loop_quit(mainloop);
}

static gboolean run_func(void *data)
{
	if (gargc < 2 || (gargc > 1 && gargv[1] && (g_strcmp0(gargv[1], "help") == 0 && gargc == 2))) {
		printf("%s help create|join|send", gargv[0]);
		g_main_loop_quit(mainloop);
		return FALSE;
	}

	if (g_strcmp0(gargv[1], "create") == 0) {
		if (gargc == 3) {
			create(gargv[2], NULL);
		} else if (gargc == 4) {
			create(gargv[2], gargv[3]);
		}
	}

	if (g_strcmp0(gargv[1], "join") == 0) {
		if (gargc == 3) {
			join(gargv[2], NULL);
		} else if (gargc == 4) {
			join(gargv[2], gargv[3]);
		}
	}

	if (g_strcmp0(gargv[1], "send") == 0) {
		if (gargc > 4) {
			send(gargv[2]);
		}
	}

	return FALSE;
}

int main(int argc, char **argv)
{
	aul_launch_init(NULL, NULL);

	gargc = argc;
	gargv = argv;

	g_idle_add(run_func, NULL);

	mainloop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(mainloop);

	return 0;
}
