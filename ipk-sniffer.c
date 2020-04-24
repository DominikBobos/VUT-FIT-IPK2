/*******************************************
	NAME:			PACKET SNIFFER
	DESCRIPTION:	Packet analyser for IPK
	AUTHOR:			Dominik Boboš (xbobos00)
	AC.YEAR:		2019/2020
********************************************/


#include <stdio.h>				//////////////////////////
#include <stdlib.h> 			//						//
#include <stdbool.h>			//						//
#include <ctype.h>				//	C-dependencies		//
#include <string.h>				//						//
#include <getopt.h>				//						//
#include <time.h>				//						//
#include <sys/types.h>			//////////////////////////
#include <netdb.h>				//////////////////////////
#include <sys/socket.h>			//						//
#include <arpa/inet.h>			//						//
#include <pcap.h>				//						//
#include <net/ethernet.h> 		//						//
#include <netinet/in.h>			// Libs for sniffing 	//
#include <netinet/ip.h>			//						//
#include <netinet/tcp.h>		//						//
#include <netinet/udp.h>		//						//
#include <netinet/if_ether.h>	//						//
#include <netinet/ip6.h>		//////////////////////////


/*
*	Struct with needed info 
* 	for output 
*/
struct pckt_info 
{
    char src_addr[1025];	//contains source IP or FQDN
    char dest_addr[1025];	//contains source IP or FQDN
    unsigned src_port;		//contains source  PORT
    unsigned dest_port;		//contains destination  PORT
    int header_size;		// size of the full packet header
};


//global variables as insurance for pcap_loop end
int PNUM = 1;
int LOOPS = 1;


/*
*	Function for right output format
*	prints spaces 'count' times
*/
void add_space(int count)
{
	if (count <= 22)	//because of the extra space between 8 bytes
		--count;
	char spaces[count];
	for (int i = 0; i < count; i++)
		spaces[i] = ' ';
	spaces[count] = '\0';
	printf("%s",spaces);
}


/*
*	Prints data to output
*	format: <TIMESTAMP> (src)IP|FQDN : port > (dest)IP|FQDN : port
*	<whole packet with separated header from load>
*/
void print_data(char *time, long microsec, struct pckt_info packet_info, 
				const unsigned data_len, const u_char *data)
{
	printf("%s.%ld %s : %u > %s : %u\n\n",time, microsec, 
		packet_info.src_addr, packet_info.src_port, 
		packet_info.dest_addr, packet_info.dest_port );
	int for_ascii = 0;							// variables for printing in ascii
	int header_end = packet_info.header_size;	// header size
	char ascii;									// variables for printing in ascii
	int end_case = 0;							// to correctly show first column
	for (int i = 0; i < (int)data_len/16+1; i++) {
		if (i*16 < header_end && header_end <= (i+1)*16)
			printf("0x%04x",end_case = header_end);
		else if (i*16 < (int)data_len && (int)data_len <= (i+1)*16)
			printf("0x%04x",(int)data_len);
		else 
			printf("0x%04x",end_case += 16);

		for (int k = 0; k < 16; k++)
		{
			if (i*16+k == (int)data_len) {add_space((16 - k)*3+1); break;}
			if (i*16+k == header_end) {add_space((16 - k)*3+1); break;}
			if (k == 8) {printf(" ");}
        	printf(" %02x", data[i*16+k] & 0xff);
        }	
        printf("  ");
        for (int k = 0; k < 16; k++)
		{
			if (i*16+k == (int)data_len) {break;}
			if (i*16+k == header_end) {printf("\n"); break;}
			if (k == 8) {printf(" ");}
			for_ascii = data[i*16+k] - 127;
			ascii = for_ascii;
			if (!isprint((int)ascii)) {ascii = 46;}
        	printf("%c", ascii);
        }
        printf("\n");
    }   
    printf("--------------------------------------------------------------------------\n\n");
}

/* 
*	Gets FQDN from IP, when FQDN could not be found
*	returns IP address back
*	MODIFICATED from
*	SOURCE: https://cboard.cprogramming.com/c-programming/169902-getnameinfo-example-problem.html
* 	AUTHOR: algorism
*/
char *host_name(struct in_addr ip_addr)
{
	char *ip = malloc(NI_MAXHOST * sizeof(char));	//buffer about size of the max host
	if (!ip) 
	{	return NULL;}

	strcpy(ip, inet_ntoa(ip_addr));	//converts to readable address
	if (ip == NULL)
	{
		perror("inet_ntoa"); 
		return NULL;
	}

	struct sockaddr_in sa;
	char *node = malloc(NI_MAXHOST * sizeof(char));
	if (!node) 
	{	return NULL;}
 
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	 
	inet_pton(AF_INET, ip, &sa.sin_addr);
 
	int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
						  node, sizeof(node),
						  NULL, 0, NI_NAMEREQD);   
	if (res) 
	{	return ip;}
	else 
	{	return node;}
}


/*
*	Function for processing UDP protocol
*	gets buffer and function gets from it
*	source and destination port and
*	source and destination ip's from IP header
*	returns struct pckt_info
* 	It is modification from 
* 	SOURCE: https://gist.github.com/fffaraz/7f9971463558e9ea9545
*	AUTHOR: Faraz Fallahi 
*/
struct pckt_info udp_packet(const u_char * buffer)
{
	LOOPS++;
	struct pckt_info header;
	int iphdr_len;
     
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    iphdr_len = iph->ip_hl*4;
     
    struct udphdr *udph = (struct udphdr*)(buffer + iphdr_len + sizeof(struct ether_header));   
    int udphdr_len =  sizeof(struct ether_header) + iphdr_len + sizeof udph;
     
    strcpy(header.src_addr,host_name(iph->ip_src));
    strcpy(header.dest_addr,host_name(iph->ip_dst));
    header.src_port = ntohs(udph->uh_sport);
    header.dest_port = ntohs(udph->uh_dport);
    header.header_size = udphdr_len;
    printf("___________________________________UDP____________________________________\n");
    return header;
}


/*
*	Function for processing TCP protocol
*	gets buffer and function gets from it
*	source and destination port and
*	source and destination ip's from IP header
*	returns struct pckt_info
* 	It is modification from 
* 	SOURCE: https://gist.github.com/fffaraz/7f9971463558e9ea9545
*	AUTHOR: Faraz Fallahi 
*/
struct pckt_info tcp_packet(const u_char * buffer)
{
	LOOPS++;
	struct pckt_info header;
    int iphdr_len;
     
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    iphdr_len = iph->ip_hl*4;

    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdr_len + sizeof(struct ether_header));
    int tcphdr_len =  sizeof(struct ether_header) + iphdr_len + tcph->th_off*4;
     
    char *temp_src = host_name(iph->ip_src);
    char *temp_dest = host_name(iph->ip_dst);
    strcpy(header.src_addr, temp_src);
    strcpy(header.dest_addr, temp_dest);
    free(temp_src);
	free(temp_dest);
    header.src_port = ntohs(tcph->th_sport);
    header.dest_port = ntohs(tcph->th_dport);
    header.header_size = tcphdr_len;
    printf("___________________________________TCP____________________________________\n");
    return header;
}


/*
*	Gets the whole packet, calls functions for packet parsing
* 	depending of protocol type
*	MODIFICATED fucntion from:
* 	SOURCE: https://gist.github.com/fffaraz/7f9971463558e9ea9545
*	AUTHOR: Faraz Fallahi 
*/
void callback(u_char *args, const struct pcap_pkthdr* pkthdr,const u_char* buffer)
{
	struct ether_header *p = (struct ether_header *) buffer;
	bool ipv6 = false;
	// if (ntohs(p->ether_type) == ETHERTYPE_IPV6) {     // if ETHERTYPE is IPV6, flag is set to true
 //        ipv6 = true;
 //    }
	args = NULL; // for not having a warning of unused variable
	struct pckt_info packet_info;	// to save values for printing the data
    const unsigned int data_len = (pkthdr->len);
    const u_char *data = (buffer);
	char time[30];
	strftime(time,sizeof(time),"%H:%M:%S", localtime(&pkthdr->ts.tv_sec));

	//Get the IP Header part of this packet , excluding the ethernet header
	struct ip *iph = (struct ip*)(buffer + sizeof(struct ether_header));
	switch (iph->ip_p) //Check the Protocol and do accordingly...
	{
		case 6:  //TCP Protocol
			packet_info = tcp_packet(buffer);
			break;
		 
		case 17: //UDP Protocol
			packet_info = udp_packet(buffer);
			break;
	}
	print_data(time, pkthdr->ts.tv_usec, packet_info, data_len, data);

    if (LOOPS > PNUM) 
		{exit(0);}	//not needed on mac, but needed for linux
}

/*
*	Parses command line arguments
*	Loads value from arguments to program variables 
*	-h for help
*/
bool args_parse(int argc, char *argv[], char *iface, char *port, int *pnum, int *tcp, int *udp)
{
	static const struct option longopts[] = 
	{
		{.name = "tcp", .has_arg = no_argument, .val = 't'},
		{.name = "udp", .has_arg = no_argument, .val = 'u'},
		// {},
	};
	for (;;) 
	{
		int opt = getopt_long(argc, argv, "i:p:n:tuh", longopts, NULL);
		if (opt == -1)
			break;
		switch (opt) {
		case 'i':
			if (strlen(optarg) > 19)
			{
				fprintf(stderr, "Parameter for INTERFACE could not be longer than 9 characters!\n");
				return 1;
			}
			strcpy(iface, optarg);
			break;
		case 'p':
			if (strlen(optarg) > 9)
			{
				fprintf(stderr, "Parameter for PORT could not be longer than 9numbers!\n");
				return 1;
			}
			char temp_port[15] = "port ";
			strcat(temp_port,optarg);
			strcpy(port, temp_port);
			break;
		case 'n':
			*pnum = strtol(optarg, NULL, 10);
			break;
		case 't':
			*tcp = 1;
			break;
		case 'u':
			*udp = 1;
			break;
		case 'h':
		default:
			printf("HELP:\n");
			puts("no parameters = lists all available interfaces");
			puts("-i <interface> interface, on which packet sniffer works");
			puts("-p <port_number> port on which we listen");
			puts("-t | --tcp shows only tcp packets");
			puts("-u | --udp shows only udp packets");
			puts("-n <packets_count> shows n packets (default is 1)");
			return false;
		}
	}
	return true;
}

int main(int argc, char *argv[])
{
	char iface[20], port[15]; 
	int pnum =0;
	int tcp=0;
	int udp = 0;
	char errbuf[PCAP_ERRBUF_SIZE]; 		//PCAP macro
	if (!args_parse(argc, argv, iface, port, &pnum, &tcp, &udp))
		return 1;		// when something went wrong
	if (tcp == udp) 
		tcp = udp = 0;	// that means it looks for both
	if (pnum == 0) 		// default number
	{
		pnum = 1;
		PNUM = 1;
	}   
    else 
    	PNUM = pnum;

	//when missing -i arguments, it just list all possible interfaces
	if (iface[0] == '\0')
	{
		pcap_if_t *alldevs, *dlist;
		int i = 0;
		  // Shows list of the all devices
		if (pcap_findalldevs(&alldevs, errbuf) == -1)
		{
			fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
			return 1;
		}
		// Print the list to user
		//  MODIFICATED from
		// source: https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
		// author: HIMANSHU ARORA
		printf("Available interfaces on your system:\n");
		for(dlist=alldevs; dlist; dlist=dlist->next)
		{
			printf("%dlist. %s", ++i, dlist->name);
			if (dlist->description)
				printf(" (%s)\n", dlist->description);
			else
				printf(" (No description available)\n");
		}
		return 0;
	}

	struct bpf_program fp;        // to hold compiled program 
	bpf_u_int32 pMask;            // subnet mask 
	bpf_u_int32 pNet;             // ip address

	// fetch the network address and network mask
	if (pcap_lookupnet(iface, &pNet, &pMask, errbuf) == -1)
	{
		printf("%s\n", errbuf);
		return 10;
	}

	// Opens device for sniffing
	pcap_t *opensniff = pcap_open_live(iface, BUFSIZ, 0, 1000, errbuf);
	if(opensniff == NULL)
	{
		printf("pcap_open_live() failed due to [%s]\n", errbuf);
		return 10;
	}

	// Compile the filter 
	char filter[50];
	if (tcp == 1) {strcpy(filter, "tcp ");}
	if (udp == 1) {strcpy(filter, "udp ");}
	if (port[0] != '\0' || (tcp != udp)) {strcat(filter, port);}
	else if (port[0] != '\0') {strcpy(filter, port);}
	else {strcpy(filter, "tcp or udp");}	// looks only for udp and tcp
	//source: https://www.tcpdump.org/manpages/pcap_compile.3pcap.html
	if(pcap_compile(opensniff, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)	//pNet
	{
		printf("\npcap_compile() failed\n");
		return 10;
	}

	if(pcap_setfilter(opensniff, &fp) == -1)
	{
		printf("pcap_setfilter() failed\n");
		return 10;
	}
	// Loop for catching packets, ends after pnum packets were cathed
	pcap_loop(opensniff, pnum, callback, NULL);
	return 0;
}
