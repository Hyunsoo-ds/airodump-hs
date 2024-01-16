#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>

#define WAIT_TIME 200
#define TIME_THRESHOLD 1000
#define MAX_SSID_NUM 50

struct radiotap_header{
	uint8_t it_rev;
	uint8_t it_pad;
	uint16_t it_len;
};

struct Data{
	u_char bssid[6];
	char *ssid;
	unsigned int pwr;
	unsigned int channel_num;
	unsigned int beacons;
};

struct Data *data_list[MAX_SSID_NUM];
unsigned int data_list_len = 0;


struct Data *packet_handler(struct pcap_pkthdr *pkthdr, const u_char *packet);
void process_packet(char  *erbuf, char *dev, char *filter, pcap_t *handle,unsigned int ch);
void sigint_handler(int signo);
void hope_channel(char *dev, int ch);
long long current_millisec();

int find_data(struct Data *data);
void add_data(struct Data *data);
void count_up(int idx);
void show(unsigned int ch);



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
				process_packet(erbuf, dev, filter, handle,ch);
			}
		}
	}
	else{
		printf("Put device name in argv\n");
	}

	return 0;
}

void show(unsigned int ch){
	system("clear");
	printf("----------------<airodump-hs>----------------\n");
	printf("[current_channel]: %d\n", ch);
	printf("    BSSID\t\tPWR   BEACONS\tCH	SSID\n");
	for(int i = 0 ; i < data_list_len; i++){
		printf("[%d] %02x:%02x:%02x:%02x:%02x:%02x  ",i, data_list[i]->bssid[0], data_list[i]->bssid[1], data_list[i]->bssid[2], data_list[i]->bssid[3], data_list[i]->bssid[4], data_list[i]->bssid[5]);
		printf("%d\t", data_list[i]->pwr);
		printf("%d\t ", data_list[i]->beacons);
		printf("%d\t", data_list[i]->channel_num);
		printf("%s\n", data_list[i]->ssid);
	}
	
	//printf("------------------------\n");
	
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

void count_up(int idx){
	data_list[idx]->beacons +=1;
}

void add_data(struct Data *data){
	if(data_list_len < MAX_SSID_NUM){
		data_list[data_list_len] = data;
		data_list_len ++;
	} else{
		free(data);
		//printf("MAX_SSID_NUM reached!\n");
	}
}



int find_data(struct Data *data){
	int find = 1;
	for(int idx = 0 ; idx < data_list_len; idx++){
		for(int j = 0 ; j < 6; j++){
			if(data->bssid[j] != data_list[idx]->bssid[j]){
				find = 0;
				break;
			}
		}

		if(find){
			return idx; // if correspond was found
		}

		find = 1;
	}

	return -1; // not found
}


void process_packet(char  *erbuf, char *dev, char *filter, pcap_t *handle,unsigned int ch){
	//pcap open
	handle = pcap_open_live(dev, BUFSIZ, 0,100, erbuf);
	
	if(handle == NULL){
		printf("Error: %s\n", erbuf);
		exit(1);
	}

	struct bpf_program fp;
	const u_char *packet;
	struct pcap_pkthdr header;
	struct Data *temp_data;

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
		//printf("time_interval: %lld \n", time_interval);
		start_from_now = current - start_time;

		if(packet == NULL)
			break;

	        temp_data  = packet_handler(&header, packet);
		
		int idx = find_data(temp_data);

		//printf("find_data result: %d \n", idx);
		

		
		if(idx == -1){
			add_data(temp_data);
		} else {
			//printf("[DEBUG] idx: %d counted up \n", idx);
			count_up(idx);
			free(temp_data);
		}
		
		/*
		fprintf(stdout, "PWR: %d dBm\n", temp_data->pwr);
		fprintf(stdout, "CH: %d\n", temp_data->channel_num);
		fprintf(stdout, "ESSID string: %s\n", temp_data->ssid);
		fprintf(stdout, "Beacons: %d\n", temp_data->beacons);
		fprintf(stdout, "bssid stirng: %02x:%02x:%02x:%02x:%02x:%02x\n", temp_data->bssid[0], temp_data->bssid[1], temp_data->bssid[2], temp_data->bssid[3], temp_data->bssid[4], temp_data->bssid[5]);*/
		
	
		show(ch);


		if(time_interval > WAIT_TIME) break;

	}while(start_from_now < TIME_THRESHOLD);
	//pcap_dispatch(handle, 1, packet_handler, NULL);

	
}

void sigint_handler(int signo){
	printf("Good Bye..!\n");
	exit(0);
}

struct Data *packet_handler(struct pcap_pkthdr *pkthdr, const u_char *packet){
	

	const u_char *essid;
	const u_char *pwr;
	const u_char *channel;
	const u_char *bssid;
	unsigned int essid_len;

	struct radiotap_header *rtaphdr;
	struct Data *data = malloc(sizeof(struct Data));

	rtaphdr = (struct radiotap_header *) packet;

	bssid = packet + 40;// on beacon frame HIGHLIGHT
	essid = packet + 62;
	essid_len = *(packet + 61);
	pwr = packet + 22;// on radiotap header
	
	data->pwr = pwr[0] - 256;
	channel = packet + 14;
	int channelFreq = channel[1] * 256 + channel[0];	
	data->channel_num = (channelFreq - 2407) / 5;

	data->beacons = 1;
	//printf("ch: %d\n", channel_num);

	data->ssid = malloc(essid_len * sizeof(u_char)+1);
	unsigned int i = 0;
	while(essid[i] > 0x1){
		data->ssid[i] = essid[i];
		i++;
	}

	data->ssid[i] = '\0';

	for(int i=0; i < 6; i++){
		data->bssid[i] = *(bssid+i);
	}

	/*
	fprintf(stdout, "PWR: %d dBm\n", data->pwr);
	fprintf(stdout, "AP Frequency: %iMhz\n", channelFreq);
	fprintf(stdout, "ESSID length: %i bytes\n", data->essidLen[0]);
	fprintf(stdout, "ESSID string: %s\n", data->ssid);
	fprintf(stdout, "BSSID stirng: %02X:%02X:%02X:%02X:%02X:%02X\n", data->bssid[0], data->bssid[1], data->bssid[2], data->bssid[3], data->bssid[4], data->bssid[5]);
*/
	return data;
}	

