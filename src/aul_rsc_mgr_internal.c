/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <libxml/tree.h>

#include <dlog.h>
#include <bundle.h>

#include "aul_rsc_mgr_internal.h"

static char *_get_attribute(xmlNode *xml_node, const char *name)
{
	xmlChar *val;
	char *attr = NULL;

	val = xmlGetProp(xml_node, (const xmlChar *)name);
	if (val) {
		attr = strdup((const char *)val);
		xmlFree(val);
	}

	return attr;
}

static void _get_attribute_into_bundle(xmlNode *xml_node, const char *name,
		bundle *b)
{
	char *attr;

	attr = _get_attribute(xml_node, name);
	if (attr)
		bundle_add_str(b, name, attr);
}

static int _parse_node(xmlNode *xml_node, GList **nodes)
{
	resource_node_t *node;

	if (strcmp((char *)xml_node->name, "node"))
		return -1;

	node = calloc(1, sizeof(resource_node_t));
	node->folder = _get_attribute(xml_node, "folder");
	/* why we should use bundle here? */
	node->attr = bundle_create();
	_get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_SCREEN_DPI,
			node->attr);
	_get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_SCREEN_DPI_RANGE,
			node->attr);
	_get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_SCREEN_WIDTH_RANGE,
			node->attr);
	_get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_SCREEN_LARGE,
			node->attr);
	_get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_SCREEN_BPP,
			node->attr);
	_get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_PLATFORM_VER,
			node->attr);
	_get_attribute_into_bundle(xml_node, RSC_NODE_ATTR_LANGUAGE,
			node->attr);

	*nodes = g_list_append(*nodes, node);

	return 0;
}

static char *_get_group_type(xmlNode *xml_node)
{
	static const char delim[] = "-";
	char *str;
	char *tok;
	char *ptr;

	/* copy original string */
	str = strdup((const char *)xml_node->name);
	tok = strtok_r(str, delim, &ptr);
	/* not a group element */
	if (tok == NULL || strcmp(tok, "group"))
		return NULL;
	tok = strtok_r(NULL, delim, &ptr);
	/* invalid element */
	if (tok == NULL)
		return NULL;
	ptr = strdup(tok);
	free(str);

	return ptr;
}

static int _parse_group(xmlNode *xml_node, GList **groups)
{
	xmlNode *tmp;
	char *type;
	resource_group_t *group;

	type = _get_group_type(xml_node);
	if (type == NULL)
		return -1;

	group = calloc(1, sizeof(resource_group_t));
	group->type = type;
	group->folder = _get_attribute(xml_node, "folder");

	for (tmp = xml_node->children; tmp; tmp = tmp->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;
		if (_parse_node(tmp, &group->node_list))
			continue;
	}

	*groups = g_list_append(*groups, group);

	return 0;
}

static int _parse_resource(xmlNode *xml_node, resource_data_t **data)
{
	xmlNode *tmp;

	*data = calloc(1, sizeof(resource_data_t));

	for (tmp = xml_node->children; tmp; tmp = tmp->next) {
		if (tmp->type != XML_ELEMENT_NODE)
			continue;
		_parse_group(tmp, &(*data)->group_list);
	}

	return 0;
}

int _resource_open(const char *path, resource_data_t **data)
{
	int ret;
	xmlDoc *doc;
	xmlNode *root;

	/* TODO: validate ? */
	doc = xmlReadFile(path, NULL, 0);
	if (doc == NULL)
		return -1;
	root = xmlDocGetRootElement(doc);

	ret = _parse_resource(root, data);

	xmlFreeDoc(doc);

	return ret;
}

static void __free_resource_node(gpointer data)
{
	resource_node_t *node = (resource_node_t *)data;

	free(node->folder);
	bundle_free(node->attr);
	free(node);
}

static void __free_resource_group(gpointer data)
{
	resource_group_t *group = (resource_group_t *)data;

	free(group->folder);
	free(group->type);

	g_list_free_full(group->node_list, __free_resource_node);

	free(group);
}

int _resource_close(resource_data_t *data)
{
	/*
	free(data->package);
	*/
	g_list_free_full(data->group_list, __free_resource_group);

	free(data);

	return 0;
}