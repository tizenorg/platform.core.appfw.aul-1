#ifndef __AUL_RSC_MGR_INTERNAL_H__
#define __AUL_RSC_MGR_INTERNAL_H__

#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "AUL_RESOURCE_MANAGER"

#define RSC_GROUP_TYPE_IMAGE "image"
#define RSC_GROUP_TYPE_LAYOUT "layout"
#define RSC_GROUP_TYPE_SOUND "sound"
#define RSC_GROUP_TYPE_BIN "bin"

#define RSC_NODE_ATTR_SCREEN_DPI "screen-dpi"
#define RSC_NODE_ATTR_SCREEN_DPI_RANGE "screen-dpi-range"
#define RSC_NODE_ATTR_SCREEN_WIDTH_RANGE "screen-width-range"
#define RSC_NODE_ATTR_SCREEN_LARGE "screen-large"
#define RSC_NODE_ATTR_SCREEN_BPP "screen-bpp"
#define RSC_NODE_ATTR_PLATFORM_VER "platform-version"
#define RSC_NODE_ATTR_LANGUAGE "language"

typedef struct {
	char *folder;
	bundle *attr;
} resource_node_t;

typedef struct {
	char *folder;
	char *type;
	GList *node_list;
} resource_group_t;

typedef struct {
	char *package;
	GList *group_list;
} resource_data_t;

int _resource_open(const char *path, resource_data_t **data);
int _resource_close(resource_data_t *data);

#endif
