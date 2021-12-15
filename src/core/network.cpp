#include "network.h"

void setup_capture(std::string ifname, void (*handler)(u_char*, const struct pcap_pkthdr* , const u_char*)) {
	pcap_if_t *devs, *dev;
	pcap_t* pd;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if (pcap_findalldevs(&devs, errbuf) == -1){
		exit(-1);
	}
	for (dev=devs; dev != NULL; dev = dev->next){
		if (std::string(dev->description).find(ifname) != std::string::npos) {
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

	while (not EXIT_FLAG) {
		int status = pcap_dispatch(pd, -1, handler, NULL);
	}
}

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
	if (ether_type == 0x0800){
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