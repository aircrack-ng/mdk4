#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

#ifdef __linux__
#include <linux/wireless.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#else
 #warning NOT COMPILING FOR LINUX - USE THE OLD FREQUENCY-HOPPING MECHANISM
#endif

#include "osdep.h"

#define MAX_CHAN_COUNT 128

int chans [MAX_CHAN_COUNT] = { 1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0 };
//int chans_5g [MAX_CHAN_COUNT] = {34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159, 161, 165, 183, 184, 185, 187, 188, 189, 192, 196, 0};
//int chans_2g_5g [MAX_CHAN_COUNT] = { 1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 100, 102, 104, 106, 108, 112, 114, 116, 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159, 161, 165, 183, 184, 185, 187, 188, 189, 192, 196, 0 };


int support_chans [MAX_CHAN_COUNT] = {0};

pthread_t *hopper = NULL;
pthread_t chan_sniffer;
int hopper_useconds = 0;

extern char *osdep_iface_in;
extern char *osdep_iface_out;

pthread_mutex_t chan_thread_mutex;

void channel_sniff()
{
	struct packet sniffed;
	struct ieee_hdr *hdr;
	int ie_type;
	int ie_len;
	unsigned char *pie_data;
	int channel;
  
	while(1) {

		sniffed = osdep_read_packet();
		if (sniffed.len == 0){
			usleep(1000);
			continue;
		}
    
		hdr = (struct ieee_hdr *) sniffed.data;
		if (hdr->type == IEEE80211_TYPE_BEACON){
			pie_data = sniffed.data + sizeof(struct ieee_hdr) + sizeof(struct beacon_fixed);
			// tag ssid
			ie_len = pie_data[1];
			pie_data += (1 + 1 + ie_len);
			
			// tag supported rates
			ie_len = pie_data[1];
			pie_data += (1 + 1 + ie_len);
			
			// tag channel
			channel = pie_data[2];
			printf("sniff channel: %d\n", channel);
		}

		usleep(10);

	}
}

void init_channel_list()
{
	char buffer[sizeof(struct iw_range)*3];
	struct iw_range *range;
	struct iwreq iwr;
	
	int sockfd;
	int ret, i;
	int frequency;
    int chan=0;
	
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("WTF? Couldn't open socket. Something is VERY wrong...\n");
		return;
	}
	
	memset(&iwr, 0, sizeof(iwr));
	memset(buffer, 0, sizeof(buffer));
	iwr.u.data.pointer = (caddr_t)buffer;
	iwr.u.data.length = sizeof(buffer);
	iwr.u.data.flags = 0;
	
	range = (struct iw_range *) buffer;
	
	strncpy(iwr.ifr_name, osdep_iface_out, strlen(osdep_iface_in));
	printf("interface name: %s\n", iwr.ifr_name);
	
	ret = ioctl(sockfd, SIOCGIWRANGE, &iwr);
	if(ret < 0){
		perror("error siocgiwrange:");
	}else{
		
		printf("Channel number: %d\n", range->num_frequency);
		printf("Support channels: \n");
		for(i = 0; i< range->num_frequency; i++){
			
			printf("%d : m = %d, e = %d, i = %d, flags = %d \n",i, range->freq[i].m, range->freq[i].e, range->freq[i].i, range->freq[i].flags);
			/*frequency = range.freq[i].m;
			if (frequency > 100000000)
				frequency/=100000;
			else if (frequency > 1000000)
				frequency/=1000;
			
			if (frequency > 1000)
				chan = getChannelFromFrequency(frequency);
			else 
				chan = frequency;
			
			support_chans[i] = chan;
			printf("%d, ", chan);*/
		}
		
		support_chans[i] = 0;
		printf("\n");
	}
	
	// interface_in == interface_out ???
	
    //pthread_create(&chan_sniffer, NULL, (void *) channel_sniff, NULL);
}

void channel_hopper()
{
    // A simple thread to hop channels
    int cclp = 0;
    
    while (1) {
	osdep_set_channel(chans[cclp]);
	cclp++;
	if (chans[cclp] == 0) cclp = 0;
	usleep(hopper_useconds);
    }
}

void init_channel_hopper(char *chanlist, int useconds)
{
    // Channel list chans[MAX_CHAN_COUNT] has been initialized with declaration for all b/g channels
    char *token = NULL;
    int chan_cur = EOF;
    int lpos = 0;

    if (hopper) {
      printf("There is already a channel hopper running, skipping this one!\n");
    }
    
    if (chanlist == NULL) {    // No channel list given - using defaults
#ifdef __linux__
		printf("\nUsing sniffed channels for hopping every %d milliseconds.\n", useconds/1000);
		init_channel_list();
#else
		printf("\nUsing default channels for hopping every %d milliseconds.\n", useconds/1000);
#endif
    } else {

	while((token = strsep(&chanlist, ",")) != NULL) {
	    if(sscanf(token, "%d", &chan_cur) != EOF) {
		chans[lpos] = chan_cur;
		lpos++;
		if (lpos == MAX_CHAN_COUNT) {
		    fprintf(stderr, "Exceeded max channel list entries, list truncated.\n");
		    break;
		}
	    }
	}

	chans[lpos] = 0;
    }

    hopper_useconds = useconds;
    hopper = malloc(sizeof(pthread_t));
    pthread_create(hopper, NULL, (void *) channel_hopper, NULL);
}
