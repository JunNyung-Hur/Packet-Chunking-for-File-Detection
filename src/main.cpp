#define SAM_DEF
#include "common.h"
#include "worker.h"

void sigint_handler(int s) {
	std::cout << "SIGINT detected." << std::endl;
	pcap_breakloop(PD);
	pcap_close(PD);
	EXIT_FLAG = true;
}

int main(int argc, char** argv)
{
	bloom_filter bf;
	EXIT_FLAG = false;
	END_FILTERING = false;
	END_SEARCHING = false;
	PROCESSED_PKT = 0;
	bool offlineMode = false;
	std::string inputStr = "";

	if (not parse_config(argv[0])){
		std::cerr << "Failed to parse configuration file." << std::endl;
		return -1;
	}
	if (not es::init_es(ES_HOST+":"+ES_PORT, INDEX_NAME, WINDOW_SIZE, ES_SHARDS, ES_REPLICAS, ES_INDEX_INTERVAL)){
		std::cerr << "Failed to initialize Elasticserach." << std::endl;
		return -1;
	}
	if (not init_bf(&bf, INDEX_NAME, WINDOW_SIZE, BF_ERROR_RATE)){
		std::cerr << "Failed to initialize Bloom filter";
		return -1;
	}
	for (unsigned int i = 1; i < argc; i ++){
		if (std::string(argv[i]) == "-p"){
			offlineMode = true;
		} else {
			inputStr = std::string(argv[i]);
		}
	}
	std::thread filter_t(filtering_worker, bf);
	std::thread search_t(search_worker);
	std::thread monitor_t(monitoring_worker);
	std::thread network_t(setup_capture, inputStr, offlineMode);
	signal(SIGINT, sigint_handler);
	
	network_t.join();
	filter_t.join();
	search_t.join();
	monitor_t.join();
	for (auto it = CRITICAL_CHUNK_TABLE.begin(); it!= CRITICAL_CHUNK_TABLE.end(); it++){
		while((*it).second.size()) (*it).second.pop();
	}
	return 0;
}