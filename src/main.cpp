#define SAM_DEF
#include "common.h"
#include "worker.h"
#include "network.h"


void sigint_handler(int s) {
	std::cout << "SIGINT detected." << std::endl;
	EXIT_FLAG = true;
}

void packet_capture(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	if (pkthdr->len) {
		PKT_QUEUE.push(std::make_pair(packet, pkthdr->len));
	}
}

int main(int argc, char** argv)
{
	EXIT_FLAG = false;
	spark = 0;
	PROCESSED_PKT_Q = 0;
	PROCESSED_SC_Q = 0;
	signal(SIGINT, sigint_handler);

	if (not parse_config()){
		std::cerr << "Failed to parse configuration file." << std::endl;
		return -1;
	}
	if (not es::init_es(ES_ADDR, INDEX_NAME, WINDOW_SIZE, ES_SHARDS, ES_REPLICAS, ES_INDEX_INTERVAL)){
		std::cerr << "Failed to initialize Elasticserach." << std::endl;
		return -1;
	}
	bloom_filter bf = init_bf(INDEX_NAME, WINDOW_SIZE, BF_ERROR_RATE);

	std::thread filter_t(filtering_worker, bf);
	std::thread search_t(search_worker);
	setup_capture(std::string(argv[1]), packet_capture);

	filter_t.join();
	search_t.join();
	return 0;
}