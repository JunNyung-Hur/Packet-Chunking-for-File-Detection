# Packet Chunking for File Detection

## Purpose
- identifying important files transfer in network traffic

## Dependencies
The following package is required to build this project:
- boost >= 1.6.x
- libopenssl
- libcurl
- libpcap
- rapidjson 
- elasticsearch >= 7.x

## Building
```
$ make
```

## Setup
- edit "config.txt" in project root
```
# Constants
CHUNKING_WINDOW_SIZE = 128       # Making this option larger provides more accurate search quality, but fewer search files  
BLOOMFILTER_ERROR_RATE = 0.001   # It depends on your system memory, but 0.001 is enough.
THETA_C = 0.5                    # recommend using this 0.5
THETA_H = 16                     # recommend using this between 16 and 64
MTU = 1500                       # set your network MTU

# Directories location
INDEX_DIR = /home/user/index            # Directory path containing important files that need to be identified 
BLOOMFILTER_DIR = /home/user/bf         # Directory path for storing bloom filter (please make it!)
REPORT_DIR = /home/user/report          # Directory path for storing detection logs

# Elasticsearch configuration
ES_HOST = localhost          # host of your Elasticsearch
ES_PORT = 9200               # port of your Elasticsearch 
ES_SHARDS = 5 
ES_REPLICAS = 0
ES_INDEX_INTERVAL = 1        # Waiting time for indexing
INDEX_NAME = malware         # name of index where your important files are indexed

```


## Usage
1. Place your important files to the "INDEX_DIR" set in "config.txt"
2. Make directory to store bloom filter and specify that directory path to "BLOOM_FILTER_DIR" option in "config.txt"
3. run "main" with some parts of name of your Network Interface Card(NIC) or run "main" with both -p option and pcap file path
```
$ ./main "Intel(R) I211"
or
$ ./main -p /home/user/test.pcap
```
*  Do not use the "INDEX_NAME" for different dataset at the same time

## Screenshots
