#ifndef NETWORK_H
#define NETWORK_H
#include "common.h"

void setup_capture(std::string ifname, void (*handler)(u_char*, const struct pcap_pkthdr* , const u_char*));
std::string get_session_tuple(bpf_u_int32 pkt_len, const u_char* packet);
#endif