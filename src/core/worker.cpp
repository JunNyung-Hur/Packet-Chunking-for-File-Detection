#include "worker.h"

void filtering_worker(bloom_filter bf) {
	while (true){
		if (!PKT_QUEUE.size()) {
			if (EXIT_FLAG){
				break;
			} else {
				continue;
			}
		}
		std::optional<std::pair<unsigned char*, bpf_u_int32>> pktItemOpt = PKT_QUEUE.pop();
		std::pair<unsigned char*, bpf_u_int32> pktPair = *pktItemOpt;
		PROCESSED_PKT_Q++;
		std::string sessionTuple = analyze_packet(pktPair.first, pktPair.second);
		if (sessionTuple == "0_0_0_0_eth" || (int) pktPair.second < 0 || sessionTuple.find(ES_PORT) != std::string::npos) {
			delete[] pktPair.first;
			continue;
		}
		std::cout << string_format("\r(처리 대기 패킷: %d, 처리된 패킷: %d), (검색 대기 세션: %d, 검색된 세션: %d) ... ", PKT_QUEUE.size(), PROCESSED_PKT_Q, CRITICAL_CHUNK_TABLE.size(), PROCESSED_SC_Q) << std::flush;
		std::vector<std::string> chunks = ae_chunking(pktPair.first, pktPair.second, WINDOW_SIZE);
		std::vector<std::string> filteredChunks;
		for (auto it = chunks.begin(); it != chunks.end(); it++) {
			std::string trimedChunks = trim(*it);
			if (trimedChunks == "" || trimedChunks.empty()){
				continue;
			}
			if (bf.contains(*it)) {
				std::string md5Chunk = get_md5(*it);
				filteredChunks.push_back(md5Chunk);
			}
		}
		if (filteredChunks.size()) {
			double criticalRatio = (double)filteredChunks.size()/(double)chunks.size();
			if (criticalRatio >= THETA_C){
				if (CRITICAL_CHUNK_TABLE.find(sessionTuple) == CRITICAL_CHUNK_TABLE.end()){
					CRITICAL_CHUNK_TABLE.insert(std::pair(sessionTuple, ThreadsafeQueue<std::string>()));
				}
				for (auto it=filteredChunks.begin(); it != filteredChunks.end(); it++){
					CRITICAL_CHUNK_TABLE[sessionTuple].push((*it));
				}
			}
		}
		delete[] pktPair.first;
	}
	END_FILTERING = true;
}

void search_worker(){
	std::filesystem::path reportDir(REPORT_DIR);
	std::filesystem::path reportName(INDEX_NAME + string_format("_%d_%.1f_%d.txt", WINDOW_SIZE, THETA_C, THETA_H));
	std::filesystem::path reportPath = reportDir / reportName;
	std::ofstream of;
	while (true) {
		for (auto it=CRITICAL_CHUNK_TABLE.begin(); it!=CRITICAL_CHUNK_TABLE.end(); it++){
			std::vector<std::vector<std::string>> filteredChunksVec;
			while ((*it).second.size() >= THETA_H){
				std::vector<std::string> filteredChunks;
				for (unsigned int i = 0; i < THETA_H; i++){
					filteredChunks.push_back((*(*it).second.pop()));
				}
				filteredChunksVec.push_back(filteredChunks);
			}
			if (!filteredChunksVec.size()){
				continue;
			}
			std::string esRes = es::msearch(ES_HOST+":"+ES_PORT, filteredChunksVec, INDEX_NAME, WINDOW_SIZE);
			
			rapidjson::Document resJson;
			of.open(reportPath, std::ios::app);
			resJson.Parse(esRes.c_str());
			if (!resJson.IsObject()){
				std::cout << "search error1!" << std::endl;
				std::cout << esRes << std::endl;
				continue; 
			}
			if (!resJson.HasMember("responses")){
				std::cout << "search error2" << std::endl;
				std::cout << esRes << std::endl;
				continue; 
			}
			rapidjson::Value& responses = resJson["responses"];
			for (rapidjson::Value::ConstValueIterator response = responses.Begin(); response != responses.End(); response++){
				for (rapidjson::Value::ConstValueIterator hit = (*response)["hits"]["hits"].Begin(); hit != (*response)["hits"]["hits"].End(); hit++){
					of << (*it).first << "," << (*hit)["_id"].GetString() << "," << (*hit)["_score"].GetFloat() << std::endl;;
				}
			}
			of.close();
			filteredChunksVec.clear();
			PROCESSED_SC_Q ++;
		}
		if (END_FILTERING) {
			bool isRemain = false;
			for (auto it=CRITICAL_CHUNK_TABLE.begin(); it!=CRITICAL_CHUNK_TABLE.end(); it++){
				if ((*it).second.size() >= THETA_H){	
					isRemain = true;
					break;
				}
			}
			if (isRemain){
				continue;
			}
			else{
				break;
			}
		}
	}
}
