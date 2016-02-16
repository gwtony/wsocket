#ifndef THR_MONITOR_H
#define THR_MONITOR_H

#include "cJSON.h"
#include "l7server.h"

void monitor_init(cJSON *conf, struct l7_info_st *info, int num);
void monitor_destroy(void);

#endif

