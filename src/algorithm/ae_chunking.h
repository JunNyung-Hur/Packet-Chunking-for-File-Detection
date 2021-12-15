#ifndef AE_CHUNKING_H
#define AE_CHUNKING_H
#include "common.h"

std::vector<std::string> ae_chunking(const unsigned char* byteSeq, const bpf_u_int32 bytesSize, const unsigned int windowSize);
#endif