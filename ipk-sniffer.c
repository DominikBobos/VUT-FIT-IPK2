#include <stdlib.h>
#include <stdio.h>	//
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>		//surely using

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>


void callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
  static int count = 1;

  printf("\nPacket number [%d], length of this packet is: %d\n", count++, pkthdr->len);
}


bool args_parse(int argc, char *argv[], char *iface, int *port, int *pnum, int *tcp, int *udp)
{
	static const struct option longopts[] = 
	{
        {.name = "tcp", .has_arg = no_argument, .val = 't'},
        {.name = "udp", .has_arg = no_argument, .val = 'u'},
        // {},
    };
    for (;;) 
    {
        int opt = getopt_long(argc, argv, "i:p:n:tu", longopts, NULL);
        if (opt == -1)
            break;
        switch (opt) {
        case 'i':
        	printf("Using %s interface\n", optarg);
        	strcpy(iface, optarg);
        	break;
        case 'p':
        	printf("Using port = %s\n", optarg);
        	*port = strtol(optarg, NULL, 10);
        	break;
        case 'n':
        	printf("Showing %s packets\n", optarg);
        	*pnum = strtol(optarg, NULL, 10);
        	break;
        case 't':
        	printf("Got t\n");
        	*tcp = 1;
        	break;
        case 'u':
        	printf("Got u\n");
        	*udp = 1;
        	break;
        default:
        	printf("/* Unexpected option */\n");
            /* Unexpected option */
            return false;
        }
    }
	return true;
}

int main(int argc, char *argv[])
{
	char iface[10]; 
	int port, pnum, tcp, udp = 0;
	char errbuf[PCAP_ERRBUF_SIZE]; 		//velkost bufferu je PCAP zalezitost
	if (!args_parse(argc, argv, iface, &port, &pnum, &tcp, &udp))
		return 1;
	//printf("%s, %d, %d, %d, %d\n", iface, port, pnum, tcp, udp);
	if (tcp == udp)
		tcp = udp = 0;
	
	if (pnum == 0)
		pnum = 1;   // default number

	// char *device; /* Name of device (e.g. eth0, wlan0) */
 //    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

 //    /* Find a device */
 //    device = pcap_lookupdev(error_buffer);
 //    if (device == NULL) {
 //        printf("Error finding device: %s\n", error_buffer);
 //        return 1;
 //    }
 //    printf("Network device found: %s\n", device);

	//when missing -i arguments, it just list all possible interfaces
	if (iface[0] == '\0')
	{
		pcap_if_t *alldevs, *dlist;
		int i = 0;
	      // Prepare a list of all the devices
	    if (pcap_findalldevs(&alldevs, errbuf) == -1)
	    {
	        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
	        return 1;
	    }
	    // Print the list to user
	    // madehttps://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
	    printf("\nAvailable interfaces on your system:\n\n");
	    for(dlist=alldevs; dlist; dlist=dlist->next)
	    {
	        printf("%dlist. %s", ++i, dlist->name);
	        if (dlist->description)
	            printf(" (%s)\n", dlist->description);
	        else
	            printf(" (No description available)\n");
	    }
	}
	struct bpf_program fp;        /* to hold compiled program */
	bpf_u_int32 pMask;            /* subnet mask */
    bpf_u_int32 pNet;             /* ip address*/
	// fetch the network address and network mask
    pcap_lookupnet(iface, &pNet, &pMask, errbuf);

     // Now, open device for sniffing
    if (iface[3] == '\0')
    	printf("%s", iface);
    pcap_t *opensniff = pcap_open_live(iface, BUFSIZ, 0, 100, errbuf);
    
    if(opensniff == NULL)
    {
        printf("pcap_open_live() failed due to [%s]\n", errbuf);
        return 10;
    }

    // Compile the filter expression
    char filter[10];
	for (int i = 0; i < 2; i++)
	{
		if (tcp == 1)
	    	strcpy(filter, "tcp");
	    else if (udp == 1)
	    	strcpy(filter, "udp");
	    else
	    	strcpy(filter, "tcp");
		if(pcap_compile(opensniff, &fp, filter, 0, pNet) == -1)
	    {
	        printf("\npcap_compile() failed\n");
	        return 20;
	    }
	    if 	(tcp != udp) {break;}
	    else {strcpy(filter, "udp");}

		    // Set the filter compiled above
	    if(pcap_setfilter(opensniff, &fp) == -1)
	    {
	        printf("\npcap_setfilter() failed\n");
	        exit(1);
	    }

	     // For every packet received, call the callback function
	    // For now, maximum limit on number of packets is specified
	    // by user.
	    pcap_loop(opensniff, pnum, callback, NULL);

	    printf("\nDone with packet sniffing!\n");
	}

	

	return 0;
}
