#include "worker.h"

std::string get_session_tuple(bpf_u_int32 pkt_len, const u_char* packet){
	struct ether_header *ep;
	struct ip *iph; 
	struct tcphdr *tcph;
	unsigned short ether_type;
	unsigned int length = pkt_len;

	ep = (struct ether_header *)packet;
	ether_type = ntohs(ep->ether_type);// ntohs(network to host short)
	length -= sizeof(ep);
	
	std::string sip = "0";
	std::string dip = "0";
	std::string sport = "0";
	std::string dport = "0";
	std::string ptc = "eth";
	if (ether_type == ETHERTYPE_IP){
		packet += sizeof(struct ether_header);
		iph = (struct ip *)packet;
		length -= sizeof(iph);
		sip = std::string(inet_ntoa(iph->ip_src));
		dip = std::string(inet_ntoa(iph->ip_dst));
		ptc = "ip";
		if(iph->ip_p== IPPROTO_TCP) //next protocol is TCP
		{
			packet = packet + iph->ip_hl * 4;
			tcph = (struct tcphdr *)packet;	       
								//TCP Header
								//iph->ip_hl => Header length
								//ip_hl is word so ip_hl * 4
								//linux word => 4byte
			sport = std::to_string(ntohs(tcph->th_sport));
			dport = std::to_string(ntohs(tcph->th_dport));
			ptc = "tcp";
		}
	}
	std::string session_tuple = string_format("%s_%s_%s_%s_%s",
		sip.c_str(), sport.c_str(), dip.c_str(), dport.c_str(), ptc.c_str());
	return session_tuple;
}

void filtering_worker(bloom_filter bf) {
	while (true){
		if (EXIT_FLAG) break;
		if (!PKT_QUEUE.size()) {
			continue;
		}
		std::optional<std::pair<const u_char*, bpf_u_int32>> packetItemOpt = PKT_QUEUE.pop();
		std::pair<const u_char*, bpf_u_int32> packetItem = *packetItemOpt;
		PROCESSED_PKT_Q++;
		std::string session_tuple = get_session_tuple(packetItem.second, packetItem.first) ;
		std::cout << string_format("\r(%d, %d), (%d, %d) ... ", PKT_QUEUE.size(), PROCESSED_PKT_Q, SC_MAP_QUEUE.size(), PROCESSED_SC_Q) << std::flush;
		std::vector<std::string> chunks = ae_chunking(packetItem.first, packetItem.second, WINDOW_SIZE);
		std::vector<std::string> filteredChunks;
		for (auto it = chunks.begin(); it != chunks.end(); it++) {
			if (bf.contains(*it)) {
				std::string md5Chunk = get_md5(*it);
				filteredChunks.push_back(md5Chunk);
			}
		}
		if (filteredChunks.size()) {
			if (SC_MAP.find(session_tuple) == SC_MAP.end()) {
				SC_MAP.insert(std::pair(session_tuple, filteredChunks));
			}
			else {
				for (auto fc_it = filteredChunks.begin(); fc_it != filteredChunks.end(); fc_it++) {
					SC_MAP[session_tuple].push_back(*fc_it);
				}
			}
		}
		else if (SPARK < 150) {
			SPARK++;
		}
		else {
			for (auto sc_t_it= SC_MAP.begin(); sc_t_it != SC_MAP.end(); sc_t_it++) {
				SC_MAP_QUEUE.push(*sc_t_it);
			}
			SC_MAP.clear();
			SPARK = 0;
		}
	}
}

void search_worker(){
	result_map result;
	while (true) {
		if (not SC_MAP_QUEUE.size()) {
			if (EXIT_FLAG) break;
			else continue;
		}
		std::optional<std::pair<std::string, std::vector<std::string>>> scItemOpt = SC_MAP_QUEUE.pop();
		std::pair<std::string, std::vector<std::string>> scItem = *scItemOpt;
		PROCESSED_SC_Q++;
		std::string esRes = es::search(scItem.second, ES_ADDR, INDEX_NAME, WINDOW_SIZE);
		rapidjson::Document resJson;
		resJson.Parse(esRes.c_str());
		rapidjson::Value& hits = resJson["hits"]["hits"];
		if (not hits.Size()) {
			continue;
		}
		if (result.find(scItem.first) == result.end()) {
			hit_map new_hm;
			result.insert(std::pair(scItem.first, new_hm));
		}
		for (rapidjson::Value::ConstValueIterator hit = hits.Begin(); hit != hits.End(); hit++) {
			std::string hit_id = (*hit)["_id"].GetString();
			std::set<std::string> hit_term_set;
			for (const auto& detail : (*hit)["_explanation"]["details"].GetArray()) {
				std::string description = detail["description"].GetString();
				hit_term_set.insert(description.substr(12, 32));
			}
			if (result[scItem.first].find(hit_id) == result[scItem.first].end()) {
				set_map new_sm;
				std::set<std::string> source_set;
				for (const auto& elem : (*hit)["_source"]["data"].GetArray()) {
					source_set.insert(elem.GetString());
				}
				new_sm.insert(std::pair("source_set", source_set));
				new_sm.insert(std::pair("hit_term_set", hit_term_set));
				result[scItem.first].insert(std::pair(hit_id, new_sm));
			}
			else {
				result[scItem.first][hit_id]["hit_term_set"].insert(hit_term_set.begin(), hit_term_set.end());
			}
		}
	}
	write_report(result);
}

void write_report(result_map _result){
	rapidjson::Document result_doc;
	result_doc.SetObject();
	rapidjson::Document::AllocatorType& allocator = result_doc.GetAllocator();
	for (auto rm_it = _result.begin(); rm_it != _result.end(); rm_it++) {
		std::string session_tuple = (*rm_it).first;
		rapidjson::Value _hit_list(rapidjson::kArrayType);
		for (auto hm_it = (*rm_it).second.begin(); hm_it != (*rm_it).second.end(); hm_it++) {
			std::string hit_id = (*hm_it).first;
			set_map sm = (*hm_it).second;
			rapidjson::Value _hit_object(rapidjson::kArrayType);;
			rapidjson::Value key(hit_id.c_str(), allocator);
			double score = double(sm["hit_term_set"].size()) / double(sm["source_set"].size());
			_hit_object.PushBack(key, allocator);
			_hit_object.PushBack(score, allocator);
			_hit_list.PushBack(_hit_object, allocator);
		}
		rapidjson::Value session_key(session_tuple.c_str(), allocator);
		result_doc.AddMember(session_key, _hit_list, allocator);
	}

	typedef rapidjson::GenericStringBuffer<rapidjson::UTF8<>, rapidjson::MemoryPoolAllocator<>> StringBuffer;
	StringBuffer buf (&allocator);
	rapidjson::Writer<StringBuffer> writer(buf);
	result_doc.Accept (writer);
	std::string result_json (buf.GetString(), buf.GetSize());

	std::filesystem::path reportDir(REPORT_DIR);
	std::filesystem::path reportName(INDEX_NAME + string_format("_%d_%.0e.json", WINDOW_SIZE, BF_ERROR_RATE));
	std::filesystem::path report_path = reportDir / reportName;
	std::ofstream of (report_path);
	of << result_json;
	if (!of.good()) throw std::runtime_error ("Can't write the JSON string to the file!");
	of.close();
}