#ifndef WORKER_H
#define WORKER_H

#include "common.h"

void monitoring_worker();
void filtering_worker(bloom_filter bf);
void search_worker();

#endif