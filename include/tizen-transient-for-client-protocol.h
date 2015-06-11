#ifndef TIZEN_TRANSIENT_FOR_CLIENT_PROTOCOL_H
#define TIZEN_TRANSIENT_FOR_CLIENT_PROTOCOL_H

#ifdef  __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "wayland-client.h"

struct wl_client;
struct wl_resource;

struct tizen_transient_for;

extern const struct wl_interface tizen_transient_for_interface;

struct tizen_transient_for_listener {
	/**
	 * done - (none)
	 * @child_id: (none)
	 */
	void (*done)(void *data,
		     struct tizen_transient_for *tizen_transient_for,
		     uint32_t child_id);
};

static inline int
tizen_transient_for_add_listener(struct tizen_transient_for *tizen_transient_for,
				 const struct tizen_transient_for_listener *listener, void *data)
{
	return wl_proxy_add_listener((struct wl_proxy *) tizen_transient_for,
				     (void (**)(void)) listener, data);
}

#define TIZEN_TRANSIENT_FOR_SET	0

static inline void
tizen_transient_for_set_user_data(struct tizen_transient_for *tizen_transient_for, void *user_data)
{
	wl_proxy_set_user_data((struct wl_proxy *) tizen_transient_for, user_data);
}

static inline void *
tizen_transient_for_get_user_data(struct tizen_transient_for *tizen_transient_for)
{
	return wl_proxy_get_user_data((struct wl_proxy *) tizen_transient_for);
}

static inline void
tizen_transient_for_destroy(struct tizen_transient_for *tizen_transient_for)
{
	wl_proxy_destroy((struct wl_proxy *) tizen_transient_for);
}

static inline void
tizen_transient_for_set(struct tizen_transient_for *tizen_transient_for, uint32_t child_id, uint32_t parent_id)
{
	wl_proxy_marshal((struct wl_proxy *) tizen_transient_for,
			 TIZEN_TRANSIENT_FOR_SET, child_id, parent_id);
}

#ifdef  __cplusplus
}
#endif

#endif
