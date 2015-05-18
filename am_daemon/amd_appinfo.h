#ifndef __AUL_AMD_APPINFO_H_
#define __AUL_AMD_APPINFO_H_

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
};

int appinfo_init(void);
void appinfo_fini(void);

const struct appinfo *appinfo_insert(struct appinfomgr *cf, const char *filename);
void appinfo_delete(struct appinfomgr *cf, const char *filename);

const struct appinfo *appinfo_find(uid_t caller_uid, const char *appid);
const char *appinfo_get_value(const struct appinfo *c, enum appinfo_type type);
const char *appinfo_get_filename(const struct appinfo *c);
int appinfo_get_boolean(const struct appinfo *c, enum appinfo_type type);

typedef void (*appinfo_iter_callback)(void *user_data,
		const char *filename, const struct appinfo *c);
void appinfo_foreach(uid_t uid, appinfo_iter_callback cb, void *user_data);

#endif /* __AUL_AMD_APPINFO_H_ */
