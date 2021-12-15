﻿#define SAM_DEF
#include "common.h"
#include "worker.h"


void sigint_handler(int s) {
	std::cout << "SIGINT detected." << std::endl;
	EXIT_FLAG = true;
}

void packet_capture(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	if (pkthdr->len) {
		PKT_QUEUE.push(std::make_pair(packet, pkthdr->caplen));
	}
}

void write_report(result_map _resultMap){
	rapidjson::Document resultDoc;
	resultDoc.SetObject();
	rapidjson::Document::AllocatorType& allocator = resultDoc.GetAllocator();
	for (auto resultMapIt = _resultMap.begin(); resultMapIt != _resultMap.end(); resultMapIt++) {
		std::string sessionTuple = (*resultMapIt).first;
		rapidjson::Value _hitList(rapidjson::kArrayType);
		for (auto hitMapIt = (*resultMapIt).second.begin(); hitMapIt != (*resultMapIt).second.end(); hitMapIt++) {
			std::string hitId = (*hitMapIt).first;
			set_map setMap = (*hitMapIt).second;
			rapidjson::Value _hitObject(rapidjson::kArrayType);;
			rapidjson::Value key(hitId.c_str(), allocator);
			// double score = double(setMap["hit_term_set"].size()) / double(setMap["source_set"].size());
			double score = double(setMap["hit_term_set"].size());
			_hitObject.PushBack(key, allocator);
			_hitObject.PushBack(score, allocator);
			_hitList.PushBack(_hitObject, allocator);
		}
		rapidjson::Value sessionKey(sessionTuple.c_str(), allocator);
		resultDoc.AddMember(sessionKey, _hitList, allocator);
	}

	typedef rapidjson::GenericStringBuffer<rapidjson::UTF8<>, rapidjson::MemoryPoolAllocator<>> StringBuffer;
	StringBuffer buf (&allocator);
	rapidjson::Writer<StringBuffer> writer(buf);
	resultDoc.Accept (writer);
	std::string resultJson (buf.GetString(), buf.GetSize());

	std::filesystem::path reportDir(REPORT_DIR);
	std::filesystem::path reportName(INDEX_NAME + string_format("_%d_%.0e.json", WINDOW_SIZE, BF_ERROR_RATE));
	std::filesystem::path reportPath = reportDir / reportName;
	std::ofstream of (reportPath);
	of << resultJson;
	if (!of.good()) throw std::runtime_error ("Can't write the JSON string to the file!");
	of.close();
}

int main(int argc, char** argv)
{
	bloom_filter bf;
	EXIT_FLAG = false;
	SPARK = 0;
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
	if (not init_bf(&bf, INDEX_NAME, WINDOW_SIZE, BF_ERROR_RATE)){
		std::cerr << "Failed to initialize Bloom filter";
		return -1;
	}

	std::thread filter_t(filtering_worker, bf);
	std::thread search_t(search_worker);
	setup_capture(std::string(argv[1]), packet_capture);

	filter_t.join();
	search_t.join();
	write_report(RESULT_MAP);
	return 0;
}