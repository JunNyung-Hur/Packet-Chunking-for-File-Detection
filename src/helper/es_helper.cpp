#include "es_helper.h"

bool es::init_es(std::string _address, std::string _indexName, unsigned int _windowSize, unsigned int _shards, unsigned int _replicas, unsigned int _interval){
	if (not es::check_status(_address)){
		return false;
	}
	if (not es::has_index(_address, _indexName, _windowSize)) {
		if (not es::create_index(_address, _indexName, _windowSize, _shards, _replicas, _interval)){
			std::cout << "Error during index creation" << std::endl;
			return false;
		}
		es::bulk_index(_address, _indexName, _windowSize);
		sleep(_interval);
	}
	return true;
}

bool es::check_status(std::string _address){
	std::cout << "Check Elasticsearch is available ... " << std::flush;
	std::string reqUrl = "http://" + _address;
	CURL* curl;
	CURLcode res;
	long resCode = -1;
	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_URL, reqUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_NOBODY, 1);
	res = curl_easy_perform(curl);
	if (res == CURLE_OK){
		std::cout << "ok" << std::endl;
		return true;
	}
	else{
		std::cout << "no" << std::endl;
		return false;
	}
}

bool es::has_index(std::string _address, std::string _indexName, unsigned int _windowSize) {
	std::cout << "Check index exists ... " << std::flush;
	std::string indexName = _indexName + "_" + std::to_string(_windowSize);
	std::string reqUrl = "http://" + _address + "/" + indexName;
	CURL* curl;
	CURLcode res;
	long resCode = -1;
	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
	curl_easy_setopt(curl, CURLOPT_URL, reqUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_NOBODY, 1);

	res = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &resCode);
	curl_easy_cleanup(curl);

	if (resCode == 200) {
		std::cout << "ok" << std::endl;
		return true;
	}
	else {
		std::cout << "no" << std::endl;
		return false;
	}
}

bool es::create_index(std::string _address, std::string _indexName, unsigned int _windowSize, unsigned int _shards, unsigned int _replicas, unsigned int _interval) {
	std::string indexName = _indexName + "_" + std::to_string(_windowSize);
	std::cout << "Create index \"" + indexName + "\" ... ";
	std::string reqUrl = "http://" + _address + "/" + indexName;
	std::string mappingBody = data::get_mapping_json(_shards, _replicas, _interval);
	CURL* curl;
	CURLcode resCode;
	std::string readBuffer;
	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charset: utf-8");

	curl_easy_setopt(curl, CURLOPT_URL, reqUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, mappingBody.c_str());
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, mappingBody.size());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

	resCode = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	rapidjson::Document resJson;
	resJson.Parse(readBuffer.c_str());
	bool isSuccess = resJson["acknowledged"].GetBool();
	if (isSuccess) {
		std::cout << "ok" << std::endl;
		return true;
	}
	else {
		std::cout << "no" << std::endl;
		return false;
	}
}

bool es::bulk_index(std::string _address, std::string _indexName, unsigned int _windowSize) {
	std::string indexName = _indexName + "_" + std::to_string(_windowSize);
	std::string bulkBody = "";
	std::cout << "Start the bulk procedure ..." << std::endl;
	int dirFilesCnt = get_number_of_files(INDEX_DIR);
	int processedCnt = 1;
	for (const auto& entry : std::filesystem::directory_iterator(INDEX_DIR)) {
		std::cout << string_format("\rPreprocess for indexing (%d/%d) ... ", processedCnt, dirFilesCnt) << std::flush;
		std::ifstream is(entry.path(), std::ifstream::binary);
		if (is) {
			is.seekg(0, is.end);
			int length = (int)is.tellg();
			is.seekg(0, is.beg);

			unsigned char* buffer = (unsigned char*)malloc(length);
			is.read((char*)buffer, length);
			is.close();

			std::vector<std::string> md5Chunks;
			std::vector<std::string> chunkVec = ae_chunking(buffer, length, _windowSize);
			for (auto it = chunkVec.begin(); it != chunkVec.end(); it++) {
				std::string md5Chunk = get_md5(*it);
				md5Chunks.push_back(md5Chunk);
			}
			free(buffer);
			std::string bulkJson = data::get_bulk_json(indexName, md5Chunks, entry.path().filename().string());
			bulkBody += bulkJson + "\n";
		}
		processedCnt++;
	}
	std::cout << "ok" << std::endl;
	std::cout << "Request Bulk API ... " << std::flush;
	unsigned long successCnt = 0;
	unsigned long failCnt = 0;
	std::string reqUrl = "http://" + _address + "/_bulk";
	CURL* curl;
	CURLcode res;
	std::string readBuffer;
	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charset: utf-8");

	curl_easy_setopt(curl, CURLOPT_URL, reqUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, bulkBody.c_str());
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, bulkBody.size());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

	res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	rapidjson::Document resJson;
	resJson.Parse(readBuffer.c_str());
	rapidjson::Value items = resJson["items"].GetArray();
	for (rapidjson::Value::ConstValueIterator item = items.Begin(); item != items.End(); ++item) {
		std::string result = (*item)["index"]["result"].GetString();
		if (result == "created") {
			successCnt++;
		}
		else {
			failCnt++;
		}

	}
	std::cout << "ok" << std::endl;
	std::cout << " -> no. of successes : " << successCnt << std::endl;
	std::cout << " -> no. of failures : " << failCnt << std::endl;

	if (failCnt) {
		return false;
	}
	return true;
}


std::string es::get_number_of_document_data(std::string _address, std::string _id, std::string _indexName, unsigned int _windowSize) {
	std::string indexName = _indexName + "_" + std::to_string(_windowSize);
	std::string reqUrl = "http://" + _address + "/" + indexName + "/_doc/"+_id+"?_source=number_of_data";
	CURL* curl;
	CURLcode resCode;
	std::string readBuffer;
	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "charset: utf-8");

	curl_easy_setopt(curl, CURLOPT_URL, reqUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
	resCode = curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	return readBuffer;
}


std::string es::search(std::string _address, std::vector<std::string> _md5Chunks, std::string _indexName, unsigned int _windowSize) {
	std::string indexName = _indexName + "_" + std::to_string(_windowSize);
	std::string reqUrl = "http://" + _address + "/" + indexName + "/_search";
	std::string searchBody = data::get_query_json(_md5Chunks);
	CURL* curl;
	CURLcode resCode;
	std::string readBuffer;
	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charset: utf-8");

	curl_easy_setopt(curl, CURLOPT_URL, reqUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, searchBody.c_str());
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, searchBody.size());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
	resCode = curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	return readBuffer;
}


std::string es::msearch(std::string _address, std::vector<std::vector<std::string>> _md5ChunksVec, std::string _indexName, unsigned int _windowSize){
	std::string indexName = _indexName + "_" + std::to_string(_windowSize);
	std::string reqUrl = "http://" + _address + "/" + indexName + "/_msearch";
	std::string mSearchBody = "";
	for(auto _md5ChunksVecIt = _md5ChunksVec.begin(); _md5ChunksVecIt != _md5ChunksVec.end(); _md5ChunksVecIt++){
		mSearchBody += data::get_msearch_query_json(*_md5ChunksVecIt, indexName)+"\n";
	}

	CURL* curl;
	CURLcode resCode;
	std::string readBuffer;
	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, "Accept: application/json");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "charset: utf-8");

	curl_easy_setopt(curl, CURLOPT_URL, reqUrl.c_str());
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, mSearchBody.c_str());
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, mSearchBody.size());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
	resCode = curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	return readBuffer;
}


std::string es::data::get_query_json(std::vector<std::string> _md5Chunks) {
	rapidjson::Document query;
	query.SetObject();
	rapidjson::Document::AllocatorType& allocator = query.GetAllocator();
	query.AddMember("_source", false, allocator);
	query.AddMember("explain", true, allocator);
	query.AddMember("size", 10, allocator);
	rapidjson::Value _bool(rapidjson::kObjectType);
	rapidjson::Value _should(rapidjson::kObjectType);
	rapidjson::Value _termArray(rapidjson::kArrayType);
	for (auto md5It = _md5Chunks.begin(); md5It != _md5Chunks.end(); md5It++) {
		rapidjson::Value _term(rapidjson::kObjectType);
		rapidjson::Value _data(rapidjson::kObjectType);
		_data.AddMember("data", rapidjson::StringRef((*md5It).c_str()), allocator);
		_term.AddMember("term", _data, allocator);
		_termArray.PushBack(_term, allocator);
	}
	_should.AddMember("should", _termArray, allocator);
	_bool.AddMember("bool", _should, allocator);
	query.AddMember("query", _bool, allocator);

	rapidjson::StringBuffer querybuf;
	rapidjson::Writer<rapidjson::StringBuffer> writer(querybuf);
	query.Accept(writer);

	return querybuf.GetString();
}


std::string es::data::get_msearch_query_json(std::vector<std::string> _md5Chunks, std::string _indexName) {
	rapidjson::Document queryHeader;
	queryHeader.SetObject();
	rapidjson::Document::AllocatorType& allocator = queryHeader.GetAllocator();
	queryHeader.AddMember("index", rapidjson::StringRef(_indexName.c_str()), allocator);
	queryHeader.AddMember("search_type", rapidjson::StringRef("dfs_query_then_fetch"), allocator);

	rapidjson::StringBuffer queryHeaderBuf;
	rapidjson::Writer<rapidjson::StringBuffer> writer(queryHeaderBuf);
	queryHeader.Accept(writer);

	std::string msearch_query_json = "";
	msearch_query_json += queryHeaderBuf.GetString();
	msearch_query_json += "\n";
	msearch_query_json += es::data::get_query_json(_md5Chunks);
	return msearch_query_json;
}


std::string es::data::get_bulk_json(std::string _indexName, std::vector<std::string> _md5Chunks, std::string _fileName) {
	rapidjson::Document header;
	header.SetObject();
	rapidjson::Document::AllocatorType& allocator = header.GetAllocator();
	rapidjson::Value index(rapidjson::kObjectType);
	index.AddMember("_index", rapidjson::StringRef(_indexName.c_str()), allocator);
	index.AddMember("_id", rapidjson::StringRef(_fileName.c_str()), allocator);
	header.AddMember("index", index, allocator);

	rapidjson::Document body;
	body.SetObject();
	rapidjson::Value dataArray(rapidjson::kArrayType);
	for (auto md5It = _md5Chunks.begin(); md5It != _md5Chunks.end(); md5It++) {
		dataArray.PushBack(rapidjson::StringRef((*md5It).c_str()), allocator);
	}
	body.AddMember("data", dataArray, allocator);
	body.AddMember("number_of_data", _md5Chunks.size(), allocator);

	rapidjson::StringBuffer headerBuf;
	rapidjson::Writer<rapidjson::StringBuffer> headerWriter(headerBuf);
	header.Accept(headerWriter);

	rapidjson::StringBuffer bodyBuf;
	rapidjson::Writer<rapidjson::StringBuffer> bodyWriter(bodyBuf);
	body.Accept(bodyWriter);

	std::string bulkJson = std::string(headerBuf.GetString()) + "\n" + std::string(bodyBuf.GetString());
	return bulkJson;
}

std::string es::data::get_mapping_json(unsigned int _shards, unsigned int _replicas, unsigned int _interval) {
	rapidjson::Document mapping_json;
	mapping_json.SetObject();
	rapidjson::Document::AllocatorType& allocator = mapping_json.GetAllocator();
	rapidjson::Value settings(rapidjson::kObjectType);
	settings.AddMember("refresh_interval", "1s", allocator);
	settings.AddMember("number_of_shards", _shards, allocator);
	settings.AddMember("number_of_replicas", _replicas, allocator);
	rapidjson::Value similarity(rapidjson::kObjectType);
	rapidjson::Value scripted_one(rapidjson::kObjectType);
	scripted_one.AddMember("type", "scripted", allocator);
	rapidjson::Value script(rapidjson::kObjectType);
	script.AddMember("source", "return 1;", allocator);
	scripted_one.AddMember("script", script, allocator);
	similarity.AddMember("scripted_one", scripted_one, allocator);
	settings.AddMember("similarity", similarity, allocator);

	rapidjson::Value mappings(rapidjson::kObjectType);
	mappings.AddMember("dynamic", "strict", allocator);
	rapidjson::Value properties(rapidjson::kObjectType);
	rapidjson::Value data(rapidjson::kObjectType);
	data.AddMember("type", "text", allocator);
	data.AddMember("similarity", "scripted_one", allocator);
	properties.AddMember("data", data, allocator);
	rapidjson::Value numberOfData(rapidjson::kObjectType);
	numberOfData.AddMember("type", "integer", allocator);
	properties.AddMember("number_of_data", numberOfData, allocator);
	mappings.AddMember("properties", properties, allocator);

	mapping_json.AddMember("settings", settings, allocator);
	mapping_json.AddMember("mappings", mappings, allocator);

	rapidjson::StringBuffer mappingBuf;
	rapidjson::Writer<rapidjson::StringBuffer> writer(mappingBuf);
	mapping_json.Accept(writer);

	return mappingBuf.GetString();
}