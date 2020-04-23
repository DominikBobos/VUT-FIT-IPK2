#include <stdlib.h>	//
#include <stdio.h>	//
#include <stdbool.h>	//
#include <string.h>	//
#include <getopt.h>	//
#include <netdb.h>	//
#include <unistd.h>	//
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>	//
#include <pcap.h>		//

#include <net/ethernet.h> //
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>


struct pckt_info 
{
    char src_addr[256];
    char dest_addr[256];
    unsigned src_port;
    unsigned dest_port;
    int header_size;
};

struct addr_info
{
	struct in_addr src_addr;
	struct in_addr dest_addr;
};

struct mac_filter
{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
}__attribute__ ((packed));

char *host_name(struct in_addr ip_addr);

char *add_space(int count)
{
	char spaces[count];
	for (int i = 0; i < count; i++)
		spaces[i] = ' ';
	spaces[count] = '\0';
	return spaces;
}

struct pckt_info udp_packet(const u_char * buffer)
{
	struct pckt_info header;
	int iphdr_len;
     
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    iphdr_len = iph->ip_hl*4;
     
    struct udphdr *udph = (struct udphdr*)(buffer + iphdr_len + sizeof(struct ether_header));   
    int udphdr_len =  sizeof(struct ether_header) + iphdr_len + sizeof udph;
     
    // fprintf(stdout , "\n***********************UDP Packet*************************\n");
    strcpy(header.src_addr,host_name(iph->ip_src));
    strcpy(header.dest_addr,host_name(iph->ip_dst));
    header.src_port = ntohs(udph->uh_sport);
    header.dest_port = ntohs(udph->uh_dport);
    header.header_size = udphdr_len;
    return header;
}

struct pckt_info tcp_packet(const u_char * buffer)
{
	struct pckt_info header;
    int iphdr_len;
     
    struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    iphdr_len = iph->ip_hl*4;

    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdr_len + sizeof(struct ether_header));
             
    int tcphdr_len =  sizeof(struct ether_header) + iphdr_len + tcph->th_off*4;
     
    // fprintf(stdout , "\n***********************TCP Packet*************************\n");  

    strcpy(header.src_addr,host_name(iph->ip_src));
    strcpy(header.dest_addr,host_name(iph->ip_dst));
    header.src_port = ntohs(tcph->th_sport);
    header.dest_port = ntohs(tcph->th_dport);
    header.header_size = tcphdr_len;
    return header;
}

void callback(u_char *args, const struct pcap_pkthdr* pkthdr,const u_char* buffer)
{
	//https://stackoverflow.com/questions/5177879/display-the-contents-of-the-packet-in-c
	struct mac_filter *p = (struct mac_filter *) buffer;
	struct pckt_info packet_info;
    const unsigned int data_len = (pkthdr->len);
    const u_char *data = (buffer);     
	// printf("\nPacket number, length of this packet is: %d\n", pkthdr->len);

	int size = pkthdr->len;
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
			puts("mam UDP");
			packet_info = udp_packet(buffer);
			break;
	}
	printf("%s.%d %s : %u > %s : %u\n\n",time, pkthdr->ts.tv_usec, 
		packet_info.src_addr, packet_info.src_port, 
		packet_info.dest_addr, packet_info.dest_port );
	for (int i = 0; i < (int)data_len/16+1; i++) {
		int for_ascii = 0;
		int header_end = packet_info.header_size;
		char ascii;

		for (int k = 0; k < 16; k++)
		{
			if (i*16+k == (int)data_len) {printf("%s", add_space(16 - k)); break; }

			if (k == 8) {printf(" ");}
        	printf(" %02x", data[i*16+k] & 0xff);
        }	//printf(" %02x", data[i*16+k] & 0xff);
        printf("  ");
        for (int k = 0; k < 16; k++)
		{
			if (i*16+k == (int)data_len) {break;}
			if (k == 8) {printf(" ");}
			for_ascii = data[i*16+k] - 127;
			if (for_ascii < 33 || for_ascii > 126) 
				ascii = 46;
			else 
				ascii = for_ascii;
        	printf("%c", ascii);
        }
        printf("\n");
    }   

}



char *host_name(struct in_addr ip_addr)
{
	//https://cboard.cprogramming.com/c-programming/169902-getnameinfo-example-problem.html
	char ip[256];
	// /* Get ip in human readable form */
	// address.s_addr = pNet;
	strcpy(ip, inet_ntoa(ip_addr));
	if (ip == NULL) 
	{
		perror("inet_ntoa"); /* print error */
		return "error";
	}

	struct sockaddr_in sa;
	char node[NI_MAXHOST];
 
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	 
	inet_pton(AF_INET, ip, &sa.sin_addr);
 
	int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
						  node, sizeof(node),
						  NULL, 0, NI_NAMEREQD);   
	if (res) {return &ip;}
	else {return &node;}
}


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
		int opt = getopt_long(argc, argv, "i:p:n:tu", longopts, NULL);
		if (opt == -1)
			break;
		switch (opt) {
		case 'i':
			// printf("Using %s interface\n", optarg);
			if (strlen(optarg) > 9)
			{
				fprintf(stderr, "Parameter for INTERFACE could not be longer than 9 characters!\n");
				return 1;
			}
			strcpy(iface, optarg);
			break;
		case 'p':
			// printf("Using port = %s\n", optarg);
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
			// printf("Showing %s packets\n", optarg);
			*pnum = strtol(optarg, NULL, 10);
			break;
		case 't':
			// printf("Got t\n");
			*tcp = 1;
			break;
		case 'u':
			// printf("Got u\n");
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
	char iface[10], port[15]; 
	int pnum, tcp, udp = 0;
	char errbuf[PCAP_ERRBUF_SIZE]; 		//velkost bufferu je PCAP zalezitost
	if (!args_parse(argc, argv, iface, port, &pnum, &tcp, &udp))
		return 1;
	//printf("%s, %d, %d, %d, %d\n", iface, port, pnum, tcp, udp);
	if (tcp == udp)
		tcp = udp = 0;
	if (pnum == 0)
		pnum = 1;   // default number

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
		// made by https://www.thegeekstuff.com/2012/10/packet-sniffing-using-libpcap/
		printf("\nAvailable interfaces on your system:\n\n");
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
	struct in_addr address; /* Used for both ip & subnet https://www.devdungeon.com/content/using-libpcap-c */

	struct bpf_program fp;        /* to hold compiled program */
	bpf_u_int32 pMask;            /* subnet mask */
	bpf_u_int32 pNet;             /* ip address*/

	// fetch the network address and network mask
	if (pcap_lookupnet(iface, &pNet, &pMask, errbuf) == -1)
	{
		printf("%s\n", errbuf);
		return 10;
	}

	 // Now, open device for sniffing
	pcap_t *opensniff = pcap_open_live(iface, BUFSIZ, 0, 1000, errbuf);
	if(opensniff == NULL)
	{
		printf("pcap_open_live() failed due to [%s]\n", errbuf);
		return 10;
	}
	// Compile the filter expression
	char filter[25];
	if (tcp == 1) {strcpy(filter, "tcp ");}
	if (udp == 1) {strcpy(filter, "udp ");}
	if (port[0] != '\0' || (tcp != udp)) {strcat(filter, port);}
	else if (port[0] != '\0') {strcpy(filter, port);}
	if(pcap_compile(opensniff, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)	//pNet
	{
		printf("\npcap_compile() failed\n");
		return 20;
	}
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
	return 0;
}



 //    /* Get subnet mask in human readable form */
 //    address.s_addr = pMask;
 //    strcpy(subnet, inet_ntoa(address));
 //    if (subnet == NULL) 
 //    {
 //        perror("inet_ntoa");
 //        return 1;
 //    }

 //    printf("Device: %s\n", iface);
 //    printf("IP address: %s\n", ip);
 //    printf("Subnet mask: %s\n", subnet);

	
	// struct addrinfo hints, *info, *p;
	// int gai_result;
	// char hostname[1024];
	// hostname[1023] = '\0';
	// gethostname(hostname, 1023);

	// memset(&hints, 0, sizeof hints);
	// hints.ai_family = AF_UNSPEC; /*either IPV4 or IPV6*/
	// hints.ai_socktype = SOCK_STREAM;
	// hints.ai_flags = AI_CANONNAME;

	// if ((gai_result = getaddrinfo(hostname, "http", &hints, &info)) != 0) {
	//     fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_result));
	//     exit(1);
	// }

	// for(p = info; p != NULL; p = p->ai_next) {
	//     printf("hostname: %s\n", p->ai_canonname);
	// }

	// freeaddrinfo(info);