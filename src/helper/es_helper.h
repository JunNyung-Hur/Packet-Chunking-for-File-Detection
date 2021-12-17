#ifndef ES_HELPER_H
#define ES_HELPER_H
#include "common.h"
#include "ae_chunking.h"
#include "utils.h"

namespace es {
	bool init_es(std::string _address, std::string _indexName, unsigned int _windowSize, unsigned int _shards, unsigned int _replicas, unsigned int _interval);
	bool check_status(std::string _address);
	bool has_index(std::string _address, std::string _indexName, unsigned int _windowSize);
	bool create_index(std::string _address, std::string _indexName, unsigned int _windowSize, unsigned int _shards, unsigned int _replicas, unsigned int _interval);
	bool bulk_index(std::string _address, std::string _indexName, unsigned int _windowSize);
	std::string get_number_of_document_data(std::string _address, std::string _id, std::string _indexName, unsigned int _windowSize);
	std::string search(std::string _address, std::vector<std::string> _md5Chunks, std::string _indexName, unsigned int _windowSize);
	std::string msearch(std::string _address, std::vector<std::vector<std::string>> _md5ChunksVec, std::string _indexName, unsigned int _windowSize);
	namespace data {
		std::string get_query_json(std::vector<std::string> _md5Chunks);
		std::string get_msearch_query_json(std::vector<std::string> _md5Chunks, std::string _indexName);
		std::string get_bulk_json(std::string _indexName, std::vector<std::string> _md5Chunks, std::string _fileName);
		std::string get_mapping_json(unsigned int _shards, unsigned int _replicas, unsigned int _interval);
	}
}
#endif