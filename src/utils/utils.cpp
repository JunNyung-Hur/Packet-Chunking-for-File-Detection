#include "utils.h"

void print_chunk_arr(std::vector<std::vector<unsigned char>> _chunkArr) {
	for (auto it = _chunkArr.begin(); it != _chunkArr.end(); it++) {
		for (auto strIt = (*it).begin(); strIt != (*it).end(); strIt++) {
			printf("%c", *strIt);
		}
		printf("\n");
	}
};

int get_number_of_files(std::string _dirPath) {
	auto dirIter = std::filesystem::directory_iterator(_dirPath);

	int fileCnt = std::count_if(
		std::filesystem::begin(dirIter),
		std::filesystem::end(dirIter),
		[](auto& entry) { return std::filesystem::is_regular_file(entry); }
	);
	return fileCnt;
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

std::string get_md5(std::string _data) {
	unsigned char result[MD5_DIGEST_LENGTH];
	MD5((unsigned char*)_data.c_str(), _data.size(), result);
	std::ostringstream sout;
	sout << std::hex << std::setfill('0');
	for (long long c : result)
	{
		sout << std::setw(2) << (long long)c;
	}
	std::string md5Chunk = sout.str();
	return md5Chunk;
}

bool parse_config() {
	std::filesystem::path projectRoot = std::filesystem::path(__FILE__).parent_path().parent_path().parent_path();
	std::filesystem::path configName("config.ini");
	std::filesystem::path configPath = projectRoot / configName;
	if (not std::filesystem::exists(configPath)) {
		std::cerr << "Couldn't find config.ini." << std::endl;
		return false;
	}
	std::ifstream cFile(configPath.string());
	if (cFile.is_open())
	{
		std::string line;
		while (getline(cFile, line)) {
			line.erase(std::remove_if(line.begin(), line.end(), isspace), line.end());
			if (line[0] == '#' || line.empty())
				continue;
			auto delimiterPos = line.find("=");
			std::string key = line.substr(0, delimiterPos);
			std::string value = line.substr(delimiterPos + 1);
			if (key == "CHUNKING_WINDOW_SIZE") {
				WINDOW_SIZE = (unsigned int)std::stoi(value);
			}
			else if (key == "BLOOMFILTER_ERROR_RATE") {
				BF_ERROR_RATE = std::stof(value);
			}
			else if (key == "INDEX_DIR") {
				INDEX_DIR = value;
			}
			else if (key == "BLOOMFILTER_DIR") {
				BLOOMFILTER_DIR = value;
			}
			else if (key == "REPORT_DIR") {
				REPORT_DIR = value;
			}
			else if (key == "MTU") {
				MTU = (unsigned int)std::stoi(value);
			}
			else if (key == "ES_HOST") {
				ES_HOST = value;
			}
			else if (key == "ES_PORT") {
				ES_PORT = value;
			}
			else if (key == "ES_SHARDS") {
				ES_SHARDS = std::stoi(value);
			}
			else if (key == "ES_REPLICAS") {
				ES_REPLICAS = std::stoi(value);
			}
			else if (key == "ES_INDEX_INTERVAL") {
				ES_INDEX_INTERVAL = std::stoi(value);
			}
			else if (key == "INDEX_NAME") {
				INDEX_NAME = value;
			}
		}
	}
	else {
		std::cerr << "Couldn't open config.ini for reading.\n";
		return false;
	}
	return true;
}

double calc_mean(std::vector<double> v){
	double sum = std::accumulate(v.begin(), v.end(), 0.0);
    double mean = sum / v.size();
	return mean;
}

double calc_std(std::vector<double> v){
	double mean = calc_mean(v);

	std::vector<double> diff(v.size());
    std::transform(v.begin(), v.end(), diff.begin(), [mean](double x) { return x - mean; });
    double sq_sum = std::inner_product(diff.begin(), diff.end(), diff.begin(), 0.0);
    double stdev = std::sqrt(sq_sum / v.size());
	return stdev;
}