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


struct mac_filter
    {
        u_char ether_dhost[ETHER_ADDR_LEN];
        u_char ether_shost[ETHER_ADDR_LEN];
        u_short ether_type;
    }__attribute__ ((packed));

void print_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
     
    struct ip *iph = (struct ip *)( Buffer  + sizeof(struct ether_header) );
    iphdrlen = iph->ip_hl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ether_header));
             
    int header_size =  sizeof(struct ether_header) + iphdrlen + tcph->th_off*4;
     
    fprintf(stdout , "\n***********************TCP Packet*************************\n");  
         
    // print_ip_header(Buffer,Size);
         
    fprintf(stdout , "\n");
    fprintf(stdout , "TCP Header\n");
    fprintf(stdout , "   |-Source Port      : %u\n",ntohs(tcph->th_sport));
    fprintf(stdout , "   |-Destination Port : %u\n",ntohs(tcph->th_dport));
    fprintf(stdout , "   |-Sequence Number    : %u\n",ntohl(tcph->th_seq));
    fprintf(stdout , "   |-Acknowledge Number : %u\n",ntohl(tcph->th_ack));
    // fprintf(stdout , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    // //fprintf(stdout , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    // //fprintf(stdout , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    // fprintf(stdout , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    // fprintf(stdout , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    // fprintf(stdout , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    // fprintf(stdout , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    // fprintf(stdout , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    // fprintf(stdout , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    // fprintf(stdout , "   |-Window         : %d\n",ntohs(tcph->window));
    // fprintf(stdout , "   |-Checksum       : %d\n",ntohs(tcph->check));
    // fprintf(stdout , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    // fprintf(stdout , "\n");
    // fprintf(stdout , "                        DATA Dump                         ");
    // fprintf(stdout , "\n");
    // fprintf(stdout , "IP Header\n");
    // PrintData(Buffer,iphdrlen);
         
    // fprintf(stdout , "TCP Header\n");
    // PrintData(Buffer+iphdrlen,tcph->doff*4);
         
    // fprintf(stdout , "Data Payload\n");    
    // PrintData(Buffer + header_size , Size - header_size );
                         
    // fprintf(stdout , "\n###########################################################");
}

void callback(u_char *args, const struct pcap_pkthdr* pkthdr,const u_char* buffer)
{
	//https://stackoverflow.com/questions/5177879/display-the-contents-of-the-packet-in-c
	struct mac_filter *p = (struct mac_filter *) buffer;
    const unsigned int data_len = (pkthdr->len);
    const u_char *data = (buffer);
    int i = 0;

    printf("Type: %04hx\n", p->ether_type);

    printf(
        "Destination: %02X:%02X:%02X:%02X:%02X:%02X\n",
        p->ether_dhost[0], p->ether_dhost[1], p->ether_dhost[2],
        p->ether_dhost[3], p->ether_dhost[4], p->ether_dhost[5]
    );

    printf(
        "Sender:      %02X:%02X:%02X:%02X:%02X:%02X\n",
        p->ether_shost[0], p->ether_shost[1], p->ether_shost[2],
        p->ether_shost[3], p->ether_shost[4], p->ether_shost[5]
    );

    for (i = 0; i < data_len; i++) {
        printf("  %02x", data[i] & 0xff);
    }        
    printf("\n");
	// static int count = 1;

	printf("\nPacket number, length of this packet is: %d\n", pkthdr->len);
	// char *test = args;
 //    puts(test);
	// int size = pkthdr->len;
	char time[30];
	// printf("%s",ctime((const time_t*)&pkthdr->ts.tv_sec));
	strftime(time,sizeof(time),"%H:%M:%S", localtime(&pkthdr->ts.tv_sec));	//usec
	puts(time);
	// //Get the IP Header part of this packet , excluding the ethernet header
	// struct ip *iph = (struct ip*)(buffer + sizeof(struct ether_header));
	// switch (iph->ip_p) //Check the Protocol and do accordingly...
	// {
	// 	case 6:  //TCP Protocol
	// 		puts("mam tcp");
	// 		print_tcp_packet(buffer , size);
	// 		break;
		 
	// 	case 17: //UDP Protocol
	// 		puts("mam UDP");
	// 		// print_udp_packet(buffer , size);
	// 		break;
	// }
}


char host_name(char iface[10], bpf_u_int32 pNet, bpf_u_int32 pMask)
{
	//https://cboard.cprogramming.com/c-programming/169902-getnameinfo-example-problem.html
	char ip[15];
	// fetch the network address and network mask
	struct in_addr address; /* Used for both ip & subnet https://www.devdungeon.com/content/using-libpcap-c */
	char errbuf[PCAP_ERRBUF_SIZE]; 
	if (pcap_lookupnet(iface, &pNet, &pMask, errbuf) == -1)
	{
		printf("%s\n", errbuf);
		return 10;
	}

	/* Get ip in human readable form */
	address.s_addr = pNet;
	strcpy(ip, inet_ntoa(address));
	if (ip == NULL) 
	{
		perror("inet_ntoa"); /* print error */
		return 1;
	}

	struct sockaddr_in sa;
	char node[NI_MAXHOST];
 
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	 
	inet_pton(AF_INET, ip, &sa.sin_addr);
	/* google-public-dns-a.google.com */
 
	int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
						  node, sizeof(node),
						  NULL, 0, NI_NAMEREQD);   
	if (res) 
	{
		printf("error: %d\n", res);
		printf("%s\n", gai_strerror(res));
		return ip;
	}
	else
	{
		printf("node=%s\n", node);
		return node;
	}
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
			// printf("/* Unexpected option */\n");
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
	printf("\nDone with packet sniffing!\n");
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