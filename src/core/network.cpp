#include "network.h"

void setup_capture(std::string inputArg, bool offlineMode) {
	pcap_if_t *devs, *dev;
	pcap_t* pd;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if (offlineMode){
		pd = pcap_open_offline(inputArg.c_str(), errbuf);
		if (pd == NULL) {
			printf("Could not open pcap file %s: %s\n", inputArg.c_str(), errbuf);
			exit(-1);
		}
		int status = pcap_dispatch(pd, -1, packet_handler, NULL);
	}
	else {
		if (pcap_findalldevs(&devs, errbuf) == -1){
			exit(-1);
		}
		for (dev=devs; dev != NULL; dev = dev->next){
			if (std::string(dev->description).find(inputArg) != std::string::npos) {
				std::cout << "\"" << dev->description << "\" interface is opened."<< std::endl;
				break;
			}
		}
		if (dev == NULL) {
			std::cout << "Cannot find matching interface name" << std::endl;
			exit(-1);
		}

		pd = pcap_open_live(dev->name, MTU, 0, 100, errbuf);
		if (pd == NULL) {
			perror(errbuf);
			exit(-1);
		}
		while (!EXIT_FLAG){
			int status = pcap_dispatch(pd, -1, packet_handler, NULL);
		}
	}
}

void packet_handler(u_char* useless, const struct pcap_pkthdr* _hdr, const u_char* _pkt) {
	if (_hdr->len) {
		unsigned char* pkt = new unsigned char[_hdr->len];
		memcpy(pkt, _pkt, _hdr->len);
		PKT_QUEUE.push(std::make_pair(pkt, _hdr->len));
	}
}

std::string analyze_packet(unsigned char* _pkt, bpf_u_int32 _pkt_len){
	struct ether_header *ep;
	struct ip *iph; 
	struct tcphdr *tcph;
	unsigned short ether_type;
	
	ep = (struct ether_header *)_pkt;
	ether_type = ntohs(ep->ether_type);// ntohs(network to host short)
	std::string sip = "0";
	std::string dip = "0";
	std::string sport = "0";
	std::string dport = "0";
	std::string ptc = "eth";
	if (ether_type == 0x0800){
		_pkt_len -= sizeof(struct ether_header);
		_pkt += sizeof(struct ether_header);
		iph = (struct ip *)_pkt;
		sip = std::string(inet_ntoa(iph->ip_src));
		dip = std::string(inet_ntoa(iph->ip_dst));
		ptc = "ip";
		if(_pkt[9] == IPPROTO_TCP) //next protocol is TCP
		{
			_pkt_len -= (4 * iph->ip_hl);
			_pkt = _pkt + (4 * iph->ip_hl);
			tcph = (struct tcphdr *)_pkt;	       
								//TCP Header
								//iph->ip_hl => Header length
								//ip_hl is word so ip_hl * 4
								//linux word => 4byte
			sport = std::to_string(ntohs(tcph->th_sport));
			dport = std::to_string(ntohs(tcph->th_dport));
			ptc = "tcp";
			_pkt_len -= (4 * tcph->th_off);
			_pkt = _pkt + (4 * tcph->th_off);
		}
	}
	std::string session_tuple = string_format("%s_%s_%s_%s_%s",
		sip.c_str(), sport.c_str(), dip.c_str(), dport.c_str(), ptc.c_str());
	return session_tuple;
}