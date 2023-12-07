/* virtio_host_parser.h - virtio host CFG parser header */

/*
 * Copyright (c) 2023 Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 */

#ifndef __INCvirtioHostCfgParserh
#define __INCvirtioHostCfgParserh
#include <yaml.h>

#define YAML_PARSER "YAML-parser"

#define VM_NAME_LEN      20
#define YAML_VERSION_LEN 20
#define DEV_ARG_LEN      80
#define NODE_KEY_LEN     20
#define NODE_VAL_LEN     80

typedef unsigned long PHYS_ADDR;

struct memMap {
        PHYS_ADDR gpa;           /* guest VM physical address      */
        PHYS_ADDR hpa;           /* hypervisor VM physical address */
        size_t size;             /* memory size                    */
};

struct guestMap {
        char name[VM_NAME_LEN];     /* VM map name  */
        struct memMap *maps;        /* VM map array */
        uint32_t maps_count;        /* array length */
};

struct channel {
        uint32_t channelId;      /* channel ID               */
        char guest[VM_NAME_LEN]; /* guest name               */
        char args[DEV_ARG_LEN];  /* virtio device arguments  */
};

struct vDevice {
        uint32_t type;                  /* virtio device-type number */
        char version[YAML_VERSION_LEN]; /* virtio device version     */
        struct channel *channel;        /* channel ID array          */
        uint32_t channel_count;         /* number of channels        */
};


/* Top-level structure for storing a config */
struct guestConfig {
        char version[YAML_VERSION_LEN];
        struct guestMap *guests; /* guest array */
        uint32_t guests_count;   /* number of guests */

	struct vDevice *devices;/* virtio device array */
        uint32_t devices_count; /* number of devices   */
};

/*
 * Parses YAML configuration file
 * buf - string containing YAML configuration
 * buflen - length of the string
 * Return: 0 on success and -1 on error
 */
int virtioHostYamlLoader(char* buf, int buflen, struct guestConfig* guests);

/*
 * Print out the guests configuration
 */
void printGuestConfig(struct guestConfig* guests);

/*
 * Free guest configuration memory
 */
void freeGuestConfig(struct guestConfig* guests);

/* typedefs */
typedef struct virtioHostCfgInfo {
        struct virtioMap **pMaps;
        uint32_t mapNum;
        struct virtioHostDev *pVirtioHostDev;
        uint32_t devNum;
} VIRTIO_HOST_CFG_INFO;

typedef struct virtioHostCfgParser
{
        char *name;
        int (* parserFn)(char *, size_t, VIRTIO_HOST_CFG_INFO *);
        void (* freeDevCfgsFn)(struct virtioHostDev *);
        void (* freeDevMapsFn)(struct virtioMap **, uint32_t);
} VIRTIO_HOST_CFG_PARSER;

/* APIs for virtio host CFG parser */
extern int virtioHostParserConnect (VIRTIO_HOST_CFG_PARSER *);

#endif /* __INCvirtioHostCfgParserh */
