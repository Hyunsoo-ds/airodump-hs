#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
void packet_handler(struct pcap_pkthdr *pkthdr, const u_char *packet);
void process_packet(char  *erbuf, char *dev, char *filter, pcap_t *handle);
void sigint_handler(int signo);
void hope_channel(char *dev, int ch);
long long current_millisec();


int main(int argc, char ** argv){
	if(argc >= 2){
		signal(SIGINT, sigint_handler);

		int offset = 0;
		char *erbuf;// error buf
		char *dev;// device name
		char *filter = "type mgt subtype beacon"; // Berkeley Packet filter for WLAN beacon frame
		dev = argv[1];
		pcap_t *handle;
		while(1){
			for(int ch=1; ch < 12; ch++){
				hope_channel(dev, ch);
				process_packet(erbuf, dev, filter, handle);
			}
			
		}
	}
	else{
		printf("Put device name in argv\n");
	}

	return 0;
}

long long current_millisec(){
	struct timespec currentTime;

	clock_gettime(CLOCK_REALTIME, &currentTime);
    	long long milliseconds = currentTime.tv_sec * 1000LL + currentTime.tv_nsec / 1000000;

	return milliseconds;
}

void hope_channel(char *dev, int ch){
	char command[100];
	snprintf(command, sizeof(command), "sudo iwconfig %s channel %d", dev, ch);
	//printf("[DEBUG] Channel hoped to %d \n",ch);
	//printf("command:%s", command);
	system(command);
}

void process_packet(char  *erbuf, char *dev, char *filter, pcap_t *handle){
	//pcap open
	handle = pcap_open_live(dev, BUFSIZ, 0,100, erbuf);
	
	if(handle == NULL){
		printf("Error: %s\n", erbuf);
		exit(1);
	}

	struct bpf_program fp;
	const u_char *packet;
	struct pcap_pkthdr header;

	if(pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
		fprintf(stderr, "Error compiling BPF filter, %s\n", filter);
	if(pcap_setfilter(handle, &fp) == -1)
		fprintf(stderr, "Error Setting Libcap filter, %s\n", filter);
	

	long long start_from_now, start_time = current_millisec();

	do{
		long long before = current_millisec();
		packet = pcap_next(handle, &header);

		long long current = current_millisec();
		long long time_interval = current - before;
		printf("time_interval: %lld \n", time_interval);
		start_from_now = current - start_time;

		if(packet == NULL)
			break;

		packet_handler(&header, packet);
		printf("------------------------------\n");

		if(time_interval > 700)
			break;

	}while(start_from_now < 3000);
	//pcap_dispatch(handle, 1, packet_handler, NULL);

	
}

void sigint_handler(int signo){
	printf("Good Bye..!\n");
	exit(0);
}

void packet_handler(struct pcap_pkthdr *pkthdr, const u_char *packet){
	struct radiotap_header{
		uint8_t it_rev;
		uint8_t it_pad;
		uint16_t it_len;
	};

	struct Data{
		const u_char *bssid;
		char *ssid;
		const u_char *essidLen;
		const u_char *channel;
		signed int pwr;
	};

	const u_char *essid;
	const u_char *pwr;
	const u_char *channel;

	int offset = 0;
	struct radiotap_header *rtaphdr;
	struct Data *data = malloc(sizeof(struct Data));

	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len;

	data->bssid = packet + 40;// on beacon frame
	essid = packet + 62;
	data->essidLen = packet + 61;
	pwr = packet + 22;// on radiotap header
	
	data->pwr = pwr[0] - 256;
	channel = packet + 14;
	int channelFreq = channel[1] * 256 + channel[0];	
	int channel_num = (channelFreq - 2407) / 5;
	printf("ch: %d\n", channel_num);

	data->ssid = malloc(63);
	unsigned int i = 0;
	while(essid[i] > 0x1){
		data->ssid[i] = essid[i];
		i++;
	}

	data->ssid[i] = '\0';

	fprintf(stdout, "PWR: %d dBm\n", data->pwr);
	fprintf(stdout, "AP Frequency: %iMhz\n", channelFreq);
	fprintf(stdout, "ESSID length: %i bytes\n", data->essidLen[0]);
	fprintf(stdout, "ESSID string: %s\n", data->ssid);
	fprintf(stdout, "BSSID stirng: %02X:%02X:%02X:%02X:%02X:%02X\n", data->bssid[0], data->bssid[1], data->bssid[2], data->bssid[3], data->bssid[4], data->bssid[5]);


}	
