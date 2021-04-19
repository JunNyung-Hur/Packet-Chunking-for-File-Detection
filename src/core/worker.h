#ifndef WORKER_H
#define WORKER_H

#include "common.h"

void filtering_worker(bloom_filter bf);
void search_worker();
void write_report(result_map _result);

#endif