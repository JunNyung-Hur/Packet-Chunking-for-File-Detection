#ifndef NETWORK_H
#define NETWORK_H
#include "common.h"

void setup_capture(std::string ifname, bool offlineMode);
void packet_handler(u_char* useless, const struct pcap_pkthdr* _hdr, const u_char* _pkt);
std::string analyze_packet(unsigned char* _pkt, bpf_u_int32 _pkt_len);
#endif