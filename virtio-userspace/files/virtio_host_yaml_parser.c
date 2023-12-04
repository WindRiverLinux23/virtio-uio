/* virtio_host_yaml_parser.c - virtio host CFG parser */

/*
 * Copyright (c) 2023 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "virtio_host_parser.h"

/* defines */
#define VIRTIO_HOST_YAML_DBG
#ifdef VIRTIO_HOST_YAML_DBG

#define VIRTIO_HOST_YAML_DBG_OFF             0x00000000
#define VIRTIO_HOST_YAML_DBG_ERR             0x00000001
#define VIRTIO_HOST_YAML_DBG_INFO            0x00000002
#define VIRTIO_HOST_YAML_DBG_ALL             0xffffffff

static uint32_t virtioHostYamlDbgMask = VIRTIO_HOST_YAML_DBG_ERR;

#define DBG_MSG(mask, fmt, ...)						\
        do {								\
		if ((virtioHostYamlDbgMask & (mask)) ||			\
		    ((mask) == VIRTIO_HOST_YAML_DBG_ERR))		\
		{							\
			printf("%d: %s() " fmt, __LINE__, __func__,	\
			       ##__VA_ARGS__);				\
		}							\
	}								\
while ((0))
#else
#undef DBG_MSG
#define DBG_MSG(...)
#endif  /* VIRTIO_HOST_YAML_DBG */

#define valtohex(pair) strtoul((pair)->value, NULL, 16)
#define valtodec(pair) strtoul((pair)->value, NULL, 10)


/* locals */
struct keyValPair {
	char key[NODE_KEY_LEN];
	char value[NODE_VAL_LEN];
};

/*
 * Generic parsing functions
 */

/*
 * Check if the key matches the value
 */
static int iskey(struct keyValPair* pair, const char* key)
{
	return (strncmp(pair->key, key, sizeof(pair->key)) == 0);
}


/*
 * Get the number of elements in the sequence YAML node
 */

static uint32_t yamlGetElementsNum(yaml_node_t *node)
{
	if (node->type != YAML_SEQUENCE_NODE) {
		return 0;
	} else {
		return node->data.sequence.items.top -
			node->data.sequence.items.start;
	}
}

/*
 * Print error based on the parser parameters
 */

static void printYamlError(yaml_parser_t* parser)
{
	if (parser == NULL) {
		printf("YAML parser pointer is NULL\n");
		return;
	}
	printf("YAML parsing error %s\n",
	       strerror(errno));
	printf("Error code: %d: reason: %s\n",
	       parser->error, parser->problem);
	printf("Error offset: %ld: value: %d\n",
	       parser->problem_offset,
	       parser->problem_value);
	printf("Error context: %s\n",
	       parser->context);
}

/*
 * Get YAML key: value pair
 */
static int yamlGetKeyPair(yaml_document_t* document, yaml_node_pair_t* i_node,
	struct keyValPair* result)
{
	yaml_node_t* key_node;
	yaml_node_t* val_node;

	key_node = yaml_document_get_node(document, i_node->key);
	if (key_node == NULL) {
		return -1;
	}
	if (key_node->type != YAML_SCALAR_NODE) {
		return -1;
	} else {
		strncpy(result->key, key_node->data.scalar.value,
			sizeof(result->key));
	}

        val_node = yaml_document_get_node(document, i_node->value);
	if (val_node == NULL) {
		return -1;
	}
	if (val_node->type == YAML_SCALAR_NODE) {
		strncpy(result->value, val_node->data.scalar.value,
			sizeof(result->value));
	}

	return 0;
}

/*
 * Parse YAML memory map
 *
 * Node is a mapping of the type:
 *   - 'hpa': 0x50000000
 *     'gpa': 0xffcf0000
 *     'size': 0x10000
 *
 */
static int yamlParseSingleMemoryMap(yaml_document_t* document,
				    yaml_node_t *node,
				    struct memMap* map)
{
	yaml_node_pair_t *i_node;

	if (node->type != YAML_MAPPING_NODE) {
		return -1;
	}

	for (i_node = node->data.mapping.pairs.start;
	     i_node < node->data.mapping.pairs.top;
	     i_node++) {
		struct keyValPair result;
		if (yamlGetKeyPair(document,
				   i_node,
				   &result) < 0) {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error getting key/value pair\n");
			return -1;
		} else if (iskey(&result, "hpa")) {
			map->hpa = valtohex(&result);
		} else if (iskey(&result, "gpa")) {
			map->gpa = valtohex(&result);
		} else if (iskey(&result, "size")) {
			map->size = valtohex(&result);
		} else {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Wrong key/value pair: %s: %s\n",
				result.key, result.value);
			return -1;
		}
	}
	return 0;
}

/*
 * Parse YAML channel
 *
 * Node is a channel info of the type:
 *   - 'id': 1234
 *     'guest': 'vxworks'
 *     'args': '@tty:tty_port=/ttyVIO'
 */
static int yamlParseSingleChannel(yaml_document_t* document,
				  yaml_node_t *node,
				  struct channel* channel)
{
	yaml_node_pair_t *i_node;

	if (node->type != YAML_MAPPING_NODE) {
		return -1;
	}

	for (i_node = node->data.mapping.pairs.start;
	     i_node < node->data.mapping.pairs.top;
	     i_node++) {
		struct keyValPair result;
		if (yamlGetKeyPair(document,
				   i_node,
				   &result) < 0) {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error getting key/value pair\n");
			return -1;
		} else if (iskey(&result, "id")) {
			channel->channelId = valtodec(&result);
		} else if (iskey(&result, "guest")) {
			strncpy(channel->guest, result.value,
				sizeof(channel->guest));
		} else if (iskey(&result, "args")) {
			strncpy(channel->args, result.value,
				sizeof(channel->args));
		} else {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Wrong key/value pair: %s: %s\n",
				result.key, result.value);
			return -1;
		}
	}
	return 0;
}

void printChannel(struct channel* channel)
{
	printf("Id: %u, guest: %s, args: %s\n",
	       channel->channelId, channel->guest, channel->args);
}

/*
 * Parse guest memory maps array
 */
static int yamlParseMemoryMaps(yaml_document_t* document,
			       yaml_node_t *node,
			       struct guestMap* map)
{
	yaml_node_item_t *i_node;
	yaml_node_t *next_node;
	int i;

	if (node->type != YAML_SEQUENCE_NODE) {
		return -1;
	}

	map->maps_count = yamlGetElementsNum(node);
	map->maps = malloc(map->maps_count * sizeof(struct memMap));
	if (map->maps == NULL) {
		DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
			"Memory allocation error\n");
		map->maps_count = 0;
		return -1;
	}

	i = 0;
	for (i_node = node->data.sequence.items.start;
	     i_node < node->data.sequence.items.top;
	     i_node++) {
		next_node = yaml_document_get_node(document,
						   *i_node);
		if (next_node != NULL &&
		    yamlParseSingleMemoryMap(document, next_node,
					     &map->maps[i]) == 0) {
			i++;
		} else {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error parsing maps\n");
			return -1;
		}
	}
	return 0;
}

static void freeMaps(struct guestMap* map)
{
	if (map->maps_count > 0 && map->maps != NULL) {
		free(map->maps);
		map->maps_count = 0;
	}
}

/*
 * Parse array of channels
 */
static int yamlParseChannels(yaml_document_t* document,
			     yaml_node_t *node,
			     struct vDevice* device)
{
	yaml_node_item_t *i_node;
	yaml_node_t *next_node;
	int i;

	if (node->type != YAML_SEQUENCE_NODE) {
		return -1;
	}

	device->channel_count = yamlGetElementsNum(node);
	device->channel = malloc(device->channel_count *
				 sizeof(struct channel));
	if (device->channel == NULL) {
		DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
			"Memory allocation error\n");
		device->channel_count = 0;
		return -1;
	}
	i = 0;
	for (i_node = node->data.sequence.items.start;
	     i_node < node->data.sequence.items.top;
	     i_node++) {
		next_node = yaml_document_get_node(document,
						   *i_node);
		if (next_node != NULL &&
		    yamlParseSingleChannel(document, next_node,
					   &device->channel[i]) == 0) {
			i++;
		} else {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error parsing channels\n");
			return -1;
		}
	}
	return 0;
}

static void freeChannels(struct vDevice* device)
{
	if (device->channel_count > 0 && device->channel != NULL) {
		free(device->channel);
		device->channel_count = 0;
	}
}

/*
 * Parse YAML guest maps
 */
static int yamlParseGuestMap(yaml_document_t* document, yaml_node_t *node,
			     struct guestMap* map)
{
	yaml_node_pair_t *i_node;
	yaml_node_t *next_node;

	if (node->type != YAML_MAPPING_NODE) {
		return -1;
	}
	for (i_node = node->data.mapping.pairs.start;
	     i_node < node->data.mapping.pairs.top;
	     i_node++) {
		struct keyValPair result;
		if (yamlGetKeyPair(document,
				   i_node,
				   &result) < 0) {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error getting key/value pair\n");
			return -1;
		} else if (iskey(&result, "name")) {
			strncpy(map->name, result.value, sizeof(map->name));
		}else if (iskey(&result, "maps")) {
			next_node =
				yaml_document_get_node(document,
						       i_node->value);
			if (next_node == NULL ||
			    yamlParseMemoryMaps(document,
						next_node, map) != 0) {
				DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
					"Error parsing guest maps\n");
				return -1;
			}
		} else {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error getting key/value pair: %s: %s\n",
				result.key, result.value);
			return -1;
		}
	}
	return 0;
}

static void printGuestMap(struct guestMap* map)
{
	int i;

	printf("Guest memory map:\n");
	printf("Name: %s\n", map->name);
	printf("Total maps: %d\n", map->maps_count);

	for (i = 0; i < map->maps_count; i++) {
		printf("%d: hpa: 0x%08lx, gpa: 0x%08lx, size: 0x%08lx\n",
		       i, map->maps[i].hpa, map->maps[i].gpa, map->maps[i].size);
	}
}

/*
 * Parse YAML device
 */
static int yamlParseSingleDevice(yaml_document_t* document,
				 yaml_node_t *node,
				 struct vDevice* device)
{
	yaml_node_pair_t *i_node;
	yaml_node_t *next_node;

	if (node->type != YAML_MAPPING_NODE) {
		return -1;
	}
	for (i_node = node->data.mapping.pairs.start;
	     i_node < node->data.mapping.pairs.top;
	     i_node++) {
		struct keyValPair result;
		if (yamlGetKeyPair(document,
				   i_node,
				   &result) < 0) {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error getting key/value pair\n");
			return -1;
		} else if (iskey(&result, "type")) {
			device->type = valtodec(&result);
		} else if (iskey(&result, "version")) {
			strncpy(device->version, result.value,
				sizeof(device->version));
		} else if (iskey(&result, "channels")) {
			next_node =
				yaml_document_get_node(document,
						       i_node->value);
			if (next_node == NULL ||
			    yamlParseChannels(document,
					      next_node, device) != 0) {
				DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
					"Error parsing channels\n");
				return -1;
			}
		} else {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error getting key/value pair: %s: %s\n",
				result.key, result.value);
			return -1;
		}
	}
	return 0;
}

static void printDevice(struct vDevice* device)
{
	int i;

	printf("Device:\n");
	printf("Type: %u\n", device->type);
	printf("Version: %s\n", device->version);
	printf("Total channels: %d\n", device->channel_count);

	for (i = 0; i < device->channel_count; i++) {
		printChannel(&device->channel[i]);
	}
}

/*
 * Parse guest configuration array
 */
static int yamlParseGuests(yaml_document_t* document, yaml_node_t *node,
			   struct guestConfig* guests)
{
	yaml_node_item_t *i_node;
	yaml_node_t *next_node;
	int i;

	if (node->type != YAML_SEQUENCE_NODE) {
		return -1;
	}

	guests->guests_count = yamlGetElementsNum(node);
        guests->guests = malloc(guests->guests_count *
				sizeof(struct guestConfig));
	if (guests->guests == NULL) {
		DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
			"Memory allocation error\n");
		guests->guests_count = 0;
		return -1;
	}

	i = 0;
	for (i_node = node->data.sequence.items.start;
	     i_node < node->data.sequence.items.top;
	     i_node++) {
		next_node = yaml_document_get_node(document,
						   *i_node);
		if (next_node != NULL &&
		    yamlParseGuestMap(document, next_node,
				      &guests->guests[i]) == 0) {
			i++;
		} else {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error parsing guests\n");
			return -1;
		}
	}
	return 0;
}

/*
 * Parse devices array
 */
static int yamlParseDevices(yaml_document_t* document, yaml_node_t *node,
			   struct guestConfig* guests)
{
	yaml_node_item_t *i_node;
	yaml_node_t *next_node;
	int i;

	if (node->type != YAML_SEQUENCE_NODE) {
		return -1;
	}

	guests->devices_count = yamlGetElementsNum(node);
        guests->devices = malloc(guests->devices_count *
				 sizeof(struct vDevice));
	if (guests->devices == NULL) {
		DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
			"Memory allocation error\n");
		guests->devices_count = 0;
		return -1;
	}
	i = 0;
	for (i_node = node->data.sequence.items.start;
	     i_node < node->data.sequence.items.top;
	     i_node++) {
		next_node = yaml_document_get_node(document,
						   *i_node);
		if (next_node != NULL &&
		    yamlParseSingleDevice(document, next_node,
					  &guests->devices[i]) == 0) {
			i++;
		} else {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error parsing devices\n");
			return -1;
		}
	}
	return 0;
}

void printGuestConfig(struct guestConfig* guests)
{
	int i;

	printf("Guest config:\n");
	printf("Total guests: %d\n", guests->guests_count);

	for (i = 0; i < guests->guests_count; i++) {
		printGuestMap(&guests->guests[i]);
	}

	printf("Total devices: %d\n", guests->devices_count);
	for (i = 0; i < guests->devices_count; i++) {
		printDevice(&guests->devices[i]);
	}
}

void freeGuestConfig(struct guestConfig* guests)
{
	int i;

	for (i = 0; i < guests->guests_count; i++) {
		freeMaps(&guests->guests[i]);
	}
	if (guests->guests_count > 0) {
		free(guests->guests);
		guests->guests_count = 0;
	}

	for (i = 0; i < guests->devices_count; i++) {
		freeChannels(&guests->devices[i]);
	}
	if (guests->devices_count > 0) {
		free(guests->devices);
		guests->devices_count = 0;
	}
}

int yamlLoadConfig(yaml_document_t* document, struct guestConfig* guests)
{
	yaml_node_t *next_node;
	yaml_node_pair_t *i_node;

	yaml_node_t* node = yaml_document_get_root_node(document);

	if (node == NULL) {
		DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
			"Unable to get YAML root node\n");
		return -1;
	}
	if (node->type != YAML_MAPPING_NODE) {
		DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
			"Wrong YAML root node type: %d\n",
			node->type);
	}

	for (i_node = node->data.mapping.pairs.start;
	     i_node < node->data.mapping.pairs.top;
	     i_node++) {
		struct keyValPair result;
		if (yamlGetKeyPair(document,
				   i_node,
				   &result) < 0) {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error getting key/value pair\n");
			return -1;
		}
		if (iskey(&result, "guests")) {
			next_node =
				yaml_document_get_node(document,
						       i_node->value);
			if (next_node == NULL ||
			    yamlParseGuests(document,
					    next_node,
					    guests) != 0) {
				DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
					"Parsing guest config error\n");
				return -1;
			}
		} else if (iskey(&result, "devices")) {
			next_node =
				yaml_document_get_node(document,
						       i_node->value);
			if (next_node == NULL ||
			    yamlParseDevices(document,
					     next_node,
					     guests) != 0) {
				DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
					"Parsing devices config error\n");
				return -1;
			}
		} else if (iskey(&result, "version")) {
			strncpy(guests->version, result.value,
				sizeof(guests->version));
		} else {
			DBG_MSG(VIRTIO_HOST_YAML_DBG_ERR,
				"Error getting key/value pair: %s: %s\n",
				result.key, result.value);
		}
	}
	return 0;
}

/*
 * Parses YAML configuration file
 * buf - string containing YAML configuration
 * buflen - length of the string
 * guses - guest configuration
 * Return: 0 on success and -1 on error
 */

int parseYaml(char* buf, int buflen, struct guestConfig* guests)
{
	int result = 0;
	yaml_parser_t parser;
	yaml_document_t yaml_cfg;

	if (yaml_parser_initialize(&parser) == 0) {
		printf("YAML parser initialization error\n");
		return -1;
	}

	yaml_parser_set_input_string(&parser, buf, buflen);

	if (yaml_parser_load(&parser, &yaml_cfg) != 0) {
		if (yamlLoadConfig(&yaml_cfg, guests) != 0) {
			result = -1;
		}
		yaml_document_delete(&yaml_cfg);
	} else {
		printYamlError(&parser);
	}
	/* Cleanup */
	yaml_parser_delete(&parser);
	return result;
}
