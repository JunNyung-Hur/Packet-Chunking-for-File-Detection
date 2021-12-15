#include "worker.h"

void filtering_worker(bloom_filter bf) {
	while (true){
		if (EXIT_FLAG) break;
		if (!PKT_QUEUE.size()) {
			continue;
		}
		std::optional<std::pair<const u_char*, bpf_u_int32>> packetItemOpt = PKT_QUEUE.pop();
		std::pair<const u_char*, bpf_u_int32> packetItem = *packetItemOpt;
		PROCESSED_PKT_Q++;
		std::string sessionTuple = get_session_tuple(packetItem.second, packetItem.first) ;

		if (sessionTuple == "0_0_0_0_eth") {
			continue;
		}

		std::cout << string_format("\r(%d, %d), (%d, %d) ... ", PKT_QUEUE.size(), PROCESSED_PKT_Q, SC_MAP_QUEUE.size(), PROCESSED_SC_Q) << std::flush;
		std::pair<std::vector<std::string>, unsigned int> criticalPkt;
		std::vector<std::string> chunks = ae_chunking(packetItem.first, packetItem.second, WINDOW_SIZE);
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
			if (criticalRatio < 0.3){
				continue;
			}
			SC_MAP_QUEUE.push(std::make_pair(sessionTuple, filteredChunks));
			// if (PCTD_TABLE.find(session_tuple) == PCTD_TABLE.end()) {
			// 	std::pair<std::vector<double>, std::vector<std::string>> newCriticalPktPair;
			// 	PCTD_TABLE.insert(std::make_pair(session_tuple, newCriticalPktPair));
			// }
			// PCTD_TABLE[session_tuple].first.push_back(criticalRatio);
			// for (auto fc_it=filteredChunks.begin(); fc_it!=filteredChunks.end(); fc_it++){
				// PCTD_TABLE[session_tuple].second.push_back(*fc_it);
			// }

			// if (PCTD_TABLE[session_tuple].first.size() > 1){
			// 	std::cout << session_tuple << "-" << PCTD_TABLE[session_tuple].first.size() << std::endl;
			// 	double standardError = calc_std(PCTD_TABLE[session_tuple].first) / std::sqrt(PCTD_TABLE[session_tuple].first.size());
			// 	std::cout << "standard error: "  << standardError << std::endl;
			// 	if (standardError <= 0.02){
			// 		SC_MAP_QUEUE.push(std::make_pair(session_tuple, PCTD_TABLE[session_tuple].second));
			// 		PCTD_TABLE.erase(session_tuple);
			// 	}
			// }
		}
	}
}

void search_worker(){
	while (true) {
		if (not SC_MAP_QUEUE.size()) {
			if (EXIT_FLAG) break;
			else continue;
		}
		std::vector<std::string> sessionTupleVec;
		std::vector<std::vector<std::string>> filteredChunksVec;
		unsigned int batchSize = std::min(SC_MAP_QUEUE.size(), (unsigned long) 500);
		for (unsigned int i = 0; i < batchSize; i++){
			std::optional<std::pair<std::string, std::vector<std::string>>> scItemOpt = SC_MAP_QUEUE.pop();
			std::pair<std::string, std::vector<std::string>> scItem = *scItemOpt;
			sessionTupleVec.push_back(scItem.first);
			filteredChunksVec.push_back(scItem.second);
		}

		std::string esRes = es::msearch(ES_ADDR, filteredChunksVec, INDEX_NAME, WINDOW_SIZE);

		rapidjson::Document resJson;
		resJson.Parse(esRes.c_str());
		rapidjson::Value& responses = resJson["responses"];
		unsigned int sessionTupleIdx = 0;
		std::cout << sessionTupleIdx << sessionTupleVec[sessionTupleIdx] <<std:: endl;
		for (rapidjson::Value::ConstValueIterator response = responses.Begin(); response != responses.End(); response++){
			std::string sessionTuple = sessionTupleVec[sessionTupleIdx++];
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
		}
		PROCESSED_SC_Q += sessionTupleIdx;
	}
}
