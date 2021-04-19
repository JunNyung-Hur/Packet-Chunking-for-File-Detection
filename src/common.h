#ifndef COMMON_H
#define COMMON_H
#define NOMINMAX

#include <vector>
#include <queue>
#include <set>
#include <map>
#include <string>
#include <sstream>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <ctime>
#include <unistd.h>
#include <thread>
#include <signal.h>
#include <iomanip>

#include <openssl/md5.h>
#include <curl/curl.h>

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define RAPIDJSON_NOMEMBERITERATORCLASS
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "bf_helper.h"
#include "es_helper.h"
#include "algorithm/ae_chunking.h"
#include "utils.h"
#include "threadsafe_queue.hpp"

typedef std::map<std::string, std::set<std::string> > set_map;
typedef std::map<std::string, set_map> hit_map;
typedef std::map<std::string, hit_map> result_map;

#ifdef SAM_DEF
#define EXT
#else
#define EXT extern
#endif

/* Start extern variable */
EXT std::string INDEX_DIR;
EXT std::string DIRECTORY_NAME;
EXT std::string BLOOMFILTER_DIR;
EXT std::string REPORT_DIR;
EXT unsigned int MTU;

EXT unsigned int WINDOW_SIZE;
EXT float BF_ERROR_RATE;

EXT std::string ES_ADDR;
EXT unsigned int ES_SHARDS;
EXT unsigned int ES_REPLICAS;
EXT unsigned int ES_INDEX_INTERVAL;
EXT std::string INDEX_NAME;

EXT ThreadsafeQueue<std::pair<const u_char*, bpf_u_int32>> PKT_QUEUE;
EXT ThreadsafeQueue<std::pair<std::string, std::vector<std::string>>> SC_MAP_QUEUE; //Session Chunks Queue
EXT std::map<std::string, std::vector<std::string> > SC_MAP; //Session Chunks Table

EXT unsigned int SPARK;
EXT unsigned int PROCESSED_PKT_Q;
EXT unsigned int PROCESSED_SC_Q;

EXT bool EXIT_FLAG;
#endif 
