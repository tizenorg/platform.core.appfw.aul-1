#ifndef __AUL_AMD_APPINFO_H_
#define __AUL_AMD_APPINFO_H_

#include <sys/types.h>

struct appinfomgr;
struct appinfo;

enum appinfo_type {
	AIT_NAME,
	AIT_COMP,
	AIT_EXEC,
	AIT_TYPE,
	AIT_ONBOOT, /* start on boot: boolean */
	AIT_RESTART, /* auto restart: boolean */
	AIT_MULTI,
	AIT_HWACC,
	AIT_PERM,
	AIT_PKGID,
	AIT_PRELOAD,
	AIT_STATUS,
};

int appinfo_init(void);
void appinfo_fini(void);

int appinfo_insert(uid_t uid, const char *pkgid);

const struct appinfo *appinfo_find(uid_t caller_uid, const char *appid);
const char *appinfo_get_value(const struct appinfo *c, enum appinfo_type type);
int appinfo_set_value(struct appinfo *c, enum appinfo_type, const char *val);
const char *appinfo_get_filename(const struct appinfo *c);
int appinfo_get_boolean(const struct appinfo *c, enum appinfo_type type);

typedef void (*appinfo_iter_callback)(void *user_data,
		const char *filename, struct appinfo *c);
void appinfo_foreach(uid_t uid, appinfo_iter_callback cb, void *user_data);
void appinfo_reload(void);

#endif /* __AUL_AMD_APPINFO_H_ */
