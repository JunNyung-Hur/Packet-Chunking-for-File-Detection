CXX=g++
CFLAGS=-std=c++17 -Wno-deprecated
INC=-Isrc -Isrc/algorithm -Isrc/utils -Isrc/helper -Isrc/core -Ilib
LIBS=-lcurl -lcrypto -lpcap
OBJS=main.o ae_chunking.o bf_helper.o es_helper.o utils.o network.o worker.o

all: main.o
	$(CXX) $(OBJS) -o main $(LIBS)
	rm -f $(OBJS)

ae_chunking.o: src/algorithm/ae_chunking.h
	$(CXX) $(CFLAGS) $(INC) -c src/algorithm/ae_chunking.cpp

bf_helper.o: src/helper/bf_helper.h lib/bloomfilter.hpp
	$(CXX) $(CFLAGS) $(INC) -c src/helper/bf_helper.cpp

es_helper.o: src/helper/es_helper.h
	$(CXX) $(CFLAGS) $(INC) -c src/helper/es_helper.cpp

network.o: src/core/network.h
	$(CXX) $(CFLAGS) $(INC) -c src/core/network.cpp

utils.o: src/utils/utils.h src/utils/utils.hpp
	$(CXX) $(CFLAGS) $(INC) -c src/utils/utils.cpp

worker.o: src/core/worker.h
	$(CXX) $(CFLAGS) $(INC) -c src/core/worker.cpp

main.o: ae_chunking.o bf_helper.o es_helper.o utils.o network.o worker.o lib/threadsafe_queue.hpp
	$(CXX) $(CFLAGS) $(INC) -c src/main.cpp 

.PHONY: clean
clean:
	rm -f $(OBJS) main