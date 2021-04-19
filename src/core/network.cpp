#include "network.h"

void setup_capture(std::string ifname, void (*handler)(u_char*, const struct pcap_pkthdr* , const u_char*)) {
	pcap_if_t *net_if, *temp;
	pcap_t* pd;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	int res;
	res = pcap_findalldevs(&net_if, errbuf);
	while(net_if){
		if (std::string(net_if->name).find(ifname) == std::string::npos) {
			net_if = net_if->next;
			continue;
		}
		else {
			break;
		}
	}
	if (net_if == NULL) {
		std::cout << "Cannot find matching interface description" << std::endl;
		exit(-1);
	}

	pd = pcap_open_live(net_if->name, MTU, 0, 100, errbuf);
	if (pd == NULL) {
		perror(errbuf);
		exit(-1);
	}

	while (not EXIT_FLAG) {
		int status = pcap_dispatch(pd, -1, handler, NULL);
	}
}
