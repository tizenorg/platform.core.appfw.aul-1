 /* Copyright 2014 Manuel Bachmann <tarnyko@tarnyko.net> */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wayland-server.h>

#include <weston/compositor.h>
#include "aul-server-protocol.h"

#define AUL_PLUGIN_FILE "/tmp/aul-plugin.tmp"

int aul_surface_count;
struct wl_list aul_surface_list;

struct aul_surface {
	int32_t surface_id;
	char *appid;
	struct wl_list link;
};

struct weston_compositor *ec = NULL;


char *
aul_plugin_get_surface_appid (int surface_id)
{
	FILE *file = NULL;
	char *line, *found, *id, *appid = NULL;
	int id_len, appid_len;
	size_t len;

	file = fopen (AUL_PLUGIN_FILE, "r");
	if (!file) {
		weston_log ("aul-plugin: could not read temporary file... No surfaces set !\n");
		return NULL;
	}

	line = malloc (1);
	id = malloc (1);

	while ((getline (&line, &len, file)) != -1) {
		if ((found = strchr (line, '=')) != NULL) {
			id_len = found - line; weston_log ("ID_LEN : %d\n", id_len);
			id = realloc (id, id_len+1);
			strncpy (id, line, id_len);
			id[id_len] = '\0';

			if (surface_id == atoi (id)) {
				appid_len = strlen(line)-strlen(id)-2;
				appid = malloc (appid_len+1);
				strncpy (appid, found+1, appid_len);
				appid[appid_len] = '\0';
				break;
			}
		}
	}

	free (id);
	free (line);
	fclose (file);

	return appid;
}

void
dump_aul_plugin_file (struct wl_list surface_list)
{
	struct aul_surface *aul_surface;
	FILE *file = NULL;
	int i = 0;

	file = fopen (AUL_PLUGIN_FILE, "w");
	if (!file) {
		weston_log ("aul-plugin: could not write temporary file...\n");
		weston_log ("aul-plugin: dlopen()ing \"aul_plugin_get_surface_appid()\" will not work !\n");
		return;
	}

	wl_list_for_each (aul_surface, &surface_list, link) {
		if (i == aul_surface_count)
			break;
		fprintf (file, "%d", aul_surface->surface_id);
		fputs ("=", file);
		fprintf (file, "%s", aul_surface->appid);
		fputs ("\n", file);
		i++;
	}

	fclose (file);
}


static void
aul_set_surface_appid (struct wl_client *client, struct wl_resource *resource,
		       int32_t surface_id, const char *appid)
{
	struct weston_view *view;
	struct aul_surface *aul_surface;
	int found = 0;

	weston_log ("aul-plugin: trying to set surface %d appid to %s...\n", surface_id, appid);

	 /* is is already set ? */
	wl_list_for_each (aul_surface, &aul_surface_list, link) {
		if (aul_surface->surface_id == surface_id) {
			weston_log ("aul-plugin: surface already set, resetting.\n");
			free (aul_surface->appid);
			aul_surface->appid = strdup (appid);
			found = 1;
			break;
		}
	}

	if (found)
		goto set_end;

	 /* theorically, we should check server-side that the surface really exits ;
	  * but there may be a race condition, where the server structure lags behind the client structure. For this reason, always accept a new ID.
	  */

	weston_log ("aul-plugin: new surface, setting.\n");
	aul_surface = calloc (1, sizeof *aul_surface);
	aul_surface->surface_id = surface_id;
	aul_surface->appid = strdup (appid);
	aul_surface_count++;
	wl_list_insert (aul_surface_list.prev, &aul_surface->link);

	 /* check the ID really exists in a delayed callback */
	 /* TODO */
#if 0
	wl_list_for_each (view, &ec->view_list, link) {
		if ((view->surface) && (view->surface->resource) &&
		    (wl_resource_get_id (view->surface->resource) == surface_id)) {
			weston_log ("aul-plugin: found corresponding surface server-side...\n");
		}
	}

	if (!found)
		weston_log ("aul-plugin: did not find a corresponding surface server-side.\n");
	else
#endif
set_end:
	dump_aul_plugin_file (aul_surface_list);

	aul_send_surface_appid_set (resource, surface_id, found);
}

static void
aul_unset_surface (struct wl_client *client, struct wl_resource *resource,
		   int32_t surface_id)
{
	struct aul_surface *aul_surface, *tmp;
	int found = 0;

	weston_log ("aul-plugin: trying to unset surface %d\n", surface_id);

	wl_list_for_each (aul_surface, &aul_surface_list, link) {
		if (aul_surface->surface_id == surface_id) {
			weston_log ("aul-plugin: found surface, unsetting.\n");
			free (aul_surface->appid);
			aul_surface_count--;
			wl_list_remove (&aul_surface->link);
			free (aul_surface);
			found = 1;
			break;
		}
	}

	if (!found)
		weston_log ("aul-plugin: did not find a matching set surface.\n");
	else
		dump_aul_plugin_file (aul_surface_list);

	aul_send_surface_unset (resource, surface_id, found);
}

static void
aul_destroy (struct wl_client *client,
	     struct wl_resource *resource)
{
	struct aul_surface *aul_surface, *tmp;

	wl_list_for_each_safe (aul_surface, tmp, &aul_surface_list, link) {
		free (aul_surface->appid);
		wl_list_remove (&aul_surface->link);
		free (aul_surface);
	}

	if (access (AUL_PLUGIN_FILE, F_OK) == 0)
		unlink (AUL_PLUGIN_FILE);

	wl_resource_destroy (resource);
}


static const struct aul_interface aul_implementation = {
	aul_set_surface_appid,
	aul_unset_surface,
	aul_destroy
};

static void
bind_aul (struct wl_client *client, void *data,
	  uint32_t version, uint32_t id)
{
	struct wl_resource *resource;

	resource = wl_resource_create (client, &aul_interface,
				       1, id);
	wl_resource_set_implementation (resource, &aul_implementation,
					NULL, NULL);
}

WL_EXPORT int
module_init (struct weston_compositor *compositor,
	     int *argc, char *argv[])
{
	ec = compositor;

	weston_log ("aul-plugin: initialization.\n");

	if (wl_global_create (ec->wl_display, &aul_interface,
			      1, NULL, bind_aul) == NULL)
	{
		weston_log ("aul-plugin: could not bind the \"aul\" interface, exiting...\n");
		return -1;
	}

	aul_surface_count = 0;
	wl_list_init (&aul_surface_list);

	if (access (AUL_PLUGIN_FILE, F_OK) == 0)
		unlink (AUL_PLUGIN_FILE);

	return 0;
}
