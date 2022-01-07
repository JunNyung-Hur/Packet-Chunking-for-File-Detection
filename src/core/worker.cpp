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
		std::optional<std::pair<std::pair<unsigned char*, bpf_u_int32>, time_t>> pktItemOpt = PKT_QUEUE.pop();
		std::pair<unsigned char*, bpf_u_int32> pktPair = (*pktItemOpt).first;
		time_t pktTime = (*pktItemOpt).second;
		PROCESSED_PKT_Q++;
		std::string sessionTuple = analyze_packet(pktPair.first, pktPair.second);
		if (sessionTuple == "0_0_0_0_eth" || (int) pktPair.second < 0 || sessionTuple.find(ES_PORT) != std::string::npos) {
			delete[] pktPair.first;
			continue;
		}
		std::cout << string_format("\r(처리 대기 패킷: %d, 처리된 패킷: %d), (검색 대기 세션: %d, 검색된 세션: %d) ... ", PKT_QUEUE.size(), PROCESSED_PKT_Q, SC_MAP_QUEUE.size(), PROCESSED_SC_Q) << std::flush;
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
			if (criticalRatio >= CRITICAL_RATIO){
				SC_MAP_QUEUE.push(std::make_pair(std::make_pair(sessionTuple, filteredChunks), pktTime));
			}
		}
		delete[] pktPair.first;
	}
	END_FILTERING = true;
}

void search_worker(){
	unsigned int maxProcessingTime = 0;
	while (true) {
		if (not SC_MAP_QUEUE.size()) {
			if (END_FILTERING) break;
			else continue;
		}
		std::vector<std::string> sessionTupleVec;
		std::vector<std::vector<std::string>> filteredChunksVec;
		std::vector<time_t> pktTimeVec;
		unsigned int batchSize = std::min(SC_MAP_QUEUE.size(), (unsigned long) 1000);
		for (unsigned int i = 0; i < batchSize; i++){
			std::optional<std::pair<std::pair<std::string, std::vector<std::string>>, time_t>> scItemOpt = SC_MAP_QUEUE.pop();
			std::pair<std::string, std::vector<std::string>> scItem = (*scItemOpt).first;
			time_t pktTime = (*scItemOpt).second;
			sessionTupleVec.push_back(scItem.first);
			filteredChunksVec.push_back(scItem.second);
			pktTimeVec.push_back(pktTime);
		}

		std::string esRes = es::msearch(ES_HOST+":"+ES_PORT, filteredChunksVec, INDEX_NAME, WINDOW_SIZE);

		rapidjson::Document resJson;
		resJson.Parse(esRes.c_str());
		rapidjson::Value& responses = resJson["responses"];
		unsigned int sessionTupleIdx = 0;
		for (rapidjson::Value::ConstValueIterator response = responses.Begin(); response != responses.End(); response++){
			std::string sessionTuple = sessionTupleVec[sessionTupleIdx];
			time_t pktTime = pktTimeVec[sessionTupleIdx];
			for (rapidjson::Value::ConstValueIterator hit = (*response)["hits"]["hits"].Begin(); hit != (*response)["hits"]["hits"].End(); hit++){
				if (RESULT_MAP.find(sessionTuple) == RESULT_MAP.end()) {
					hit_map new_hm;
					RESULT_MAP.insert(std::pair(sessionTuple, new_hm));
				}
				std::string hitId = (*hit)["_id"].GetString();
				std::set<std::string> hit_term_set;
				for (const auto& detail : (*hit)["_explanation"]["details"].GetArray()) {
					std::string description = detail["description"].GetString();
					hit_term_set.insert(description.substr(12, 32));
				}
				if (RESULT_MAP[sessionTuple].find(hitId) == RESULT_MAP[sessionTuple].end()) {
					set_map new_sm;
					// std::set<std::string> source_set;
					// for (const auto& elem : (*hit)["_source"]["data"].GetArray()) {
					// 	source_set.insert(elem.GetString());
					// }
					// new_sm.insert(std::pair("source_set", source_set));
					new_sm.insert(std::pair("hit_term_set", hit_term_set));
					RESULT_MAP[sessionTuple].insert(std::pair(hitId, new_sm));
				}
				else {
					RESULT_MAP[sessionTuple][hitId]["hit_term_set"].insert(hit_term_set.begin(), hit_term_set.end());
				}
				// std::cout << sessionTuple << ": " << hit_id << "("  << RESULT_MAP[sessionTuple][hit_id]["hit_term_set"].size() << "/" << RESULT_MAP[sessionTuple][hit_id]["source_set"].size() << ")" << std::endl;
			}
			sessionTupleIdx++;
			unsigned int processingTime = std::time(0) - pktTime;
			if (processingTime > maxProcessingTime){
				maxProcessingTime = processingTime;
			}
		}
		PROCESSED_SC_Q += sessionTupleIdx;
	}
	std::cout << "max processing time: " << maxProcessingTime << std::endl;
}
