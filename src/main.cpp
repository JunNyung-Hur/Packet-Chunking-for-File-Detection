#define SAM_DEF
#include "common.h"
#include "worker.h"


void sigint_handler(int s) {
	std::cout << "SIGINT detected." << std::endl;
	EXIT_FLAG = true;
}

void write_report(){
	std::cout << "Writing report..." << std::endl;
	std::map<std::string, unsigned int> fileSizeMap;
	rapidjson::Document resultDoc;
	resultDoc.SetObject();
	rapidjson::Document::AllocatorType& allocator = resultDoc.GetAllocator();
	for (auto resultMapIt = RESULT_MAP.begin(); resultMapIt != RESULT_MAP.end(); resultMapIt++) {
		std::string sessionTuple = (*resultMapIt).first;
		rapidjson::Value _hitList(rapidjson::kArrayType);
		for (auto hitMapIt = (*resultMapIt).second.begin(); hitMapIt != (*resultMapIt).second.end(); hitMapIt++) {
			std::string hitId = (*hitMapIt).first;
			set_map setMap = (*hitMapIt).second;
			if (fileSizeMap.find(hitId) == fileSizeMap.end()){
				std::string esRes = es::get_number_of_document_data(ES_HOST+":"+ES_PORT, hitId, INDEX_NAME, WINDOW_SIZE);
				rapidjson::Document resJson;
				if (resJson.Parse(esRes.c_str()).HasParseError()){
					continue;
				}
				resJson.Parse(esRes.c_str());
				fileSizeMap.insert(std::pair(hitId, resJson["_source"]["number_of_data"].GetUint()));
			}
			double score = (double) setMap["hit_term_set"].size() / (double) fileSizeMap[hitId];
			rapidjson::Value _hitObject(rapidjson::kArrayType);;
			rapidjson::Value key(hitId.c_str(), allocator);
			_hitObject.PushBack(key, allocator);
			_hitObject.PushBack(score, allocator);
			_hitList.PushBack(_hitObject, allocator);
		}
		rapidjson::Value sessionKey(sessionTuple.c_str(), allocator);
		resultDoc.AddMember(sessionKey, _hitList, allocator);
	}
	resultDoc.AddMember("max_processing_time", MAX_PROCESSING_TIME, allocator);

	typedef rapidjson::GenericStringBuffer<rapidjson::UTF8<>, rapidjson::MemoryPoolAllocator<>> StringBuffer;
	StringBuffer buf (&allocator);
	rapidjson::Writer<StringBuffer> writer(buf);
	resultDoc.Accept (writer);
	std::string resultJson (buf.GetString(), buf.GetSize());

	std::filesystem::path reportDir(REPORT_DIR);
	std::filesystem::path reportName(INDEX_NAME + string_format("_%d.json", WINDOW_SIZE));
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
	END_FILTERING = false;
	MAX_PROCESSING_TIME = 0;
	PROCESSED_PKT_Q = 0;
	PROCESSED_SC_Q = 0;
	bool offlineMode = false;
	std::string inputStr = "";
	signal(SIGINT, sigint_handler);

	if (not parse_config()){
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
	setup_capture(inputStr, offlineMode);

	filter_t.join();
	search_t.join();
	write_report();
	return 0;
}