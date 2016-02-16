/** \file	ds_queue.h
	A simple, non-blocked, lock-free pointer queue
*/

#ifndef _AA_QUEUE_H
#define _AA_QUEUE_H

/** \cond 0 */
#include <stdint.h>
#include "cJSON.h"
/** \endcond */

typedef void (*travel_func) (intptr_t);

typedef void queue_t;

queue_t *queue_new(uint32_t max);

int queue_enqueue(queue_t *q, intptr_t data);
int queue_enqueue_nb(queue_t *q, intptr_t data);

int queue_dequeue(queue_t *q, intptr_t *data);
int queue_dequeue_nb(queue_t *q, intptr_t *data);

uint32_t queue_size(queue_t *q);

void queue_travel(queue_t *q, travel_func tf);

int queue_delete(queue_t *q);

cJSON *queue_serialize(queue_t *);

#endif
