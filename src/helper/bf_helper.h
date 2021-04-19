#ifndef BF_HELPER_H
#define BF_HELPER_H
#include "common.h"
#include "ae_chunking.h"
#include "utils.h"
#include "bloomfilter.hpp"

bool init_bf(bloom_filter *bf, std::string _indexName, int _windowSize, float _errorRate, bool verbose = true);
std::set<std::string> get_chunk_set_from_dir(std::string _indexDir, unsigned int _windowSize);
bool build_bloom_filter(bloom_filter *bf, std::set<std::string>& chunkSet, float _errorRate);
void print_bf_info(bloom_filter bf);
#endif