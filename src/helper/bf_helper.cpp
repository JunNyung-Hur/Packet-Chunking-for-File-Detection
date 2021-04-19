#include "bf_helper.h"

bool init_bf(bloom_filter *bf, std::string _indexName, int _windowSize, float _errorRate, bool verbose) {
	std::filesystem::path bfDir(BLOOMFILTER_DIR);
	std::filesystem::path bfName(_indexName + string_format("_%d_%.0e.bf", _windowSize, _errorRate));
	std::filesystem::path bf_path = bfDir / bfName;
	if (not std::filesystem::exists(bf_path)) {
		std::cout << "Start the procedure for making Bloom filter ..." << std::endl;
		if (not std::filesystem::is_directory(INDEX_DIR)){
			std::cerr << string_format("\"%s\" is invalid target index directory", INDEX_DIR.c_str()) << std::endl;
			return false;
		}
		std::set<std::string> chunkSet = get_chunk_set_from_dir(INDEX_DIR, _windowSize);
		std::cout << "Build bloom filter ... " << std::flush;
		if (not build_bloom_filter(bf, chunkSet, _errorRate)){
			std::cout << "failed" << std::endl;
			return false;
		}
		std::cout << "ok" << std::endl;
		bf->save(bf_path.u8string());
	}
	else {
		std::cout << "Load bloom filter ... ";
		bf->load(bf_path.u8string());
		std::cout << "ok" << std::endl;
	}
	if (verbose) {
		print_bf_info((*bf));
	}
	return true;
}

std::set<std::string> get_chunk_set_from_dir(std::string _indexDir, unsigned int _windowSize){
	int numFiles = get_number_of_files(_indexDir);
	int processedFiles = 0;
	std::set<std::string> chunkSet;
	for (const auto& entry : std::filesystem::directory_iterator(_indexDir)) {
		processedFiles++;
		std::cout << string_format("\rCalculate the number of chunks in files (%d/%d) ... ", processedFiles, numFiles) << std::flush;
		std::ifstream is(entry.path(), std::ifstream::binary);
		if (is) {
			is.seekg(0, is.end);
			int length = (int)is.tellg();
			is.seekg(0, is.beg);

			unsigned char* buffer = (unsigned char*)malloc(length);
			is.read((char*)buffer, length);
			is.close();

			std::vector<std::string> chunkVec = ae_chunking(buffer, length, _windowSize);
			for (auto it = chunkVec.begin(); it != chunkVec.end(); it++) {
				chunkSet.insert(*it);
			}
			free(buffer);
		}
	}
	std::cout << "ok" << std::endl;
	return chunkSet;
}

bool build_bloom_filter(bloom_filter *bf, std::set<std::string>& chunkSet, float _errorRate){
	bloom_parameters parameters;
	parameters.projected_element_count = chunkSet.size();
	parameters.false_positive_probability = _errorRate;
	parameters.compute_optimal_parameters();
	bf->set_parameters(parameters);
	for (auto it = chunkSet.begin(); it != chunkSet.end(); it++) {
		bf->insert(*it);
	}
	return true;
}

void print_bf_info(bloom_filter bf) {
	std::cout << std::endl;
	std::cout << "===== Bloom filter info ============" << std::endl;
	std::cout << "element count : " << bf.element_count() << std::endl;
	std::cout << "hash count : " << bf.hash_count() << std::endl;
	std::cout << "false positive ratio : " << bf.effective_fpp() << std::endl;
	std::cout << "====================================" << std::endl;
	std::cout << std::endl;
}