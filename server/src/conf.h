#ifndef CONF_H
#define CONF_H

#include "json_conf.h"

/**
	\def APPVERSION
		\brief Application version.
*/
#define APPVERSION				APPVERSION_MAJ "." APPVERSION_MIN

#define DEFAULT_DAEMON			1
#define DEFAULT_MONITOR_PORT	19990
#define	DEFAULT_WORK_DIR		INSTALL_PREFIX
#define DEFAULT_CONFPATH		CONFDIR"/main.conf"

#define PORT_MIN 1025
#define PORT_MAX 65535

/**
	\fn int conf_new(const char *filename)
		\brief Init the internal global configure struct and load the configure file.
		\param filename ASCIIZ string of configure file name.
		\warning Not thread safe!
*/
cJSON *conf_load(const char *filename);

/**
	\fn	int conf_delete(void)
		\brief Destroy the internal global configure struct.
*/
int conf_delete(cJSON *);

#endif

