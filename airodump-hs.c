#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char ** argv){
	//while(1){
		if(argc >= 2){
			int offset = 0;
			char *erbuf;// error buf
			char *dev;// device name
			dev = argv[1];
			pcap_t *handle;

			//pcap open
			handle = pcap_open_live(dev, BUFSIZ, 0,100, erbuf);
			if(handle == NULL){
				printf("Error: %s\n", erbuf);
				exit(1);
			}

			char *filter = "type mgt subtype beacon"; // Berkeley Packet filter for WLAN beacon frame
			struct bpf_program fp;
			//bpf_u_int32 netp; // netmask

			if(pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
				fprintf(stderr, "Error compiling BPF filter, %s\n", filter);
			if(pcap_setfilter(handle, &fp) == -1)
				fprintf(stderr, "Error Setting Libcap filter, %s\n", filter);
			
			while(1){
				pcap_dispatch(handle, 1, packet_handler, NULL);
			}

		}
		else{
			printf("Put device name in argv\n");
		}
	//}

	return 0;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet){
	struct radiotap_header{
		uint8_t it_rev;
		uint8_t it_pad;
		uint16_t it_len;
	};

	const u_char *bssid;
	const u_char *essid;
	const u_char *essidLen;
	const u_char *channel;
	const u_char *pwr;

	int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len;

	bssid = packet + 40;// on beacon frame
	essid = packet + 62;
	essidLen = packet + 61;
	pwr = packet + 22;// on radiotap header
	
	signed int rssiDbm = pwr[0] - 256;
	channel = packet + 18;
	int channelFreq = channel[1] * 256 + channel[0];	

	char *ssid = malloc(63);
	unsigned int i = 0;
	while(essid[i] > 0x1){
		ssid[i] = essid[i];
		i++;
	}

	ssid[i] = '\0';

	fprintf(stdout, "PWR: %d dBm\n", rssiDbm);
	fprintf(stdout, "AP Frequency: %iMhz\n", channelFreq);
	fprintf(stdout, "ESSID length: %i bytes\n", essidLen[0]);
	fprintf(stdout, "ESSID string: %s\n", ssid);
	fprintf(stdout, "BSSID stirng: %02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);


}	

