/*******************************************
	NAME:			PACKET SNIFFER
	DESCRIPTION:	Packet analyser for IPK
	AUTHOR:			Dominik Boboš (xbobos00)
	AC.YEAR:		2019/2020
********************************************/


#include <stdio.h>				//////////////////////////
#include <signal.h>				//						//
#include <stdlib.h> 			//						//
#include <stdbool.h>			//						//
#include <ctype.h>				//	C-dependencies		//
#include <string.h>				//						//
#include <getopt.h>				//						//
#include <time.h>				//						//
#include <sys/types.h>			//////////////////////////
#include <netdb.h>				//////////////////////////
#include <arpa/inet.h>			//						//
#include <pcap.h>				//						//
#include <netinet/ip.h>			// Libs for sniffing 	//
#include <netinet/tcp.h>		//						//
#include <netinet/udp.h>		//						//
#include <netinet/if_ether.h>	//						//
#include <netinet/ip6.h> 		//////////////////////////


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
*	Function to properly catch keyboard interruptions
*/
void intHandler() 
{
    exit(0);
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
	char *node = malloc(NI_MAXHOST * sizeof(char));	//
	if (!node) 
	{	return NULL;}
	char node_temp[NI_MAXHOST];
	strcpy(ip, inet_ntoa(ip_addr));	//converts to readable address
	if (ip == NULL)
	{
		perror("inet_ntoa"); 
		return NULL;
	}

	struct sockaddr_in sa;
	
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	 
	inet_pton(AF_INET, ip, &sa.sin_addr);
 
	int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
						  node_temp, sizeof(node_temp),
						  NULL, 0, NI_NAMEREQD); 
	if (res) 
	{	free(node); return ip;}
	else 
	{	free(ip); strcpy(node, node_temp); return node;}
}


/* 
*	Gets FQDN from IPv6, when FQDN could not be found
*	returns IP address back
*	MODIFICATED from
*	SOURCE: https://cboard.cprogramming.com/c-programming/169902-getnameinfo-example-problem.html
* 	AUTHOR: algorism
*/
char *host_nameIPv6(struct in6_addr ip_addr)
{
	char *ip = malloc(NI_MAXHOST * sizeof(char));	//INET6_ADDRSTRLEN
	if (!ip) 
	{	return NULL;}
	char *node = malloc(NI_MAXHOST * sizeof(char));	
	if (!node) 
	{	return NULL;}
	char node_temp[NI_MAXHOST];
	if (inet_ntop(AF_INET6, &ip_addr, ip, sizeof(ip)) == NULL)	//converts to readable address
	{
		perror("inet_ntop"); 
		return NULL;
	}

	struct sockaddr_in6 sa;
	
 
	memset(&sa, 0, sizeof sa);
	sa.sin6_family = AF_INET6;
	 
	inet_pton(AF_INET6, ip, &sa.sin6_addr);
 
	int res = getnameinfo((struct sockaddr*)&sa, sizeof(sa),
						  node, sizeof(node),
						  NULL, 0, NI_NAMEREQD);   
	if (res) 
	{	free(node); return ip;}
	else 
	{	free(ip); strcpy(node, node_temp); return node;}
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
*   DATE: 3rd December, 2015.
*/
struct pckt_info udp_packet(const u_char *buffer, bool ipv6)
{
	LOOPS++;
	struct pckt_info header;
	int iphdr_len;
    char *temp_src = NULL;
    char *temp_dest = NULL;

    if (ipv6 == true)
    {
    	struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
    	iphdr_len = 40; //fixed size
    	temp_src = host_nameIPv6(iph->ip6_src);
    	temp_dest = host_nameIPv6(iph->ip6_dst);
    }
    else
    {	
    	struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    	iphdr_len = iph->ip_hl*4;
    	temp_src = host_name(iph->ip_src);
    	temp_dest = host_name(iph->ip_dst);
    }
    if (temp_src == NULL|| temp_dest == NULL) {	//malloc error
    	header.header_size = -1;
    	return header;
    }
     
    struct udphdr *udph = (struct udphdr*)(buffer + iphdr_len + sizeof(struct ether_header));   
    int udphdr_len =  sizeof(struct ether_header) + iphdr_len + sizeof udph;
     
    strcpy(header.src_addr, temp_src);
    strcpy(header.dest_addr, temp_dest);
    free(temp_src);
	free(temp_dest);
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
struct pckt_info tcp_packet(const u_char * buffer, bool ipv6)
{
	LOOPS++;
	struct pckt_info header;
    int iphdr_len;
    char *temp_src = NULL;
    char *temp_dest = NULL;

    if (ipv6 == true)
    {
    	struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
    	iphdr_len = 40; //fixed size
    	temp_src = host_nameIPv6(iph->ip6_src);
    	temp_dest = host_nameIPv6(iph->ip6_dst);
    }
    else
    {	
    	struct ip *iph = (struct ip *)(buffer + sizeof(struct ether_header));
    	iphdr_len = iph->ip_hl*4;
    	temp_src = host_name(iph->ip_src);
    	temp_dest = host_name(iph->ip_dst);
    }
    if (temp_src == NULL|| temp_dest == NULL) {	//malloc error
    	header.header_size = -1;
    	return header;
    }

    struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdr_len + sizeof(struct ether_header));
    int tcphdr_len =  sizeof(struct ether_header) + iphdr_len + tcph->th_off*4;
     
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
*	MODIFICATED function from:
* 	SOURCE: https://gist.github.com/fffaraz/7f9971463558e9ea9545
*	AUTHOR: Faraz Fallahi 
*/
void callback(u_char *args, const struct pcap_pkthdr* pkthdr,const u_char* buffer)
{
	signal(SIGINT, intHandler); 		//to properly catch CTRL+C
	struct ether_header *p = (struct ether_header *) buffer;
	bool ipv6 = false;
	if (ntohs(p->ether_type) == ETHERTYPE_IPV6) {     // if ETHERTYPE is IPV6, flag is set to true
        ipv6 = true;
    }
	args = NULL; // for not having a warning of unused variable
	struct pckt_info packet_info;	// to save values for printing the data
    const unsigned int data_len = (pkthdr->len);
    const u_char *data = (buffer);
	char time[30];
	strftime(time,sizeof(time),"%H:%M:%S", localtime(&pkthdr->ts.tv_sec));

	//Get the IP Header part of this packet , excluding the ethernet header
	if (ipv6 == true)
	{
		struct ip6_hdr *iph = (struct ip6_hdr *)(buffer + sizeof(struct ether_header));
		switch (iph->ip6_ctlun.ip6_un1.ip6_un1_nxt) //Check the Protocol and do accordingly...
		{
			case 6:  //TCP Protocol
				packet_info = tcp_packet(buffer, ipv6);
				break;
			 
			case 17: //UDP Protocol
				packet_info = udp_packet(buffer, ipv6);
				break;
		}
	}
	else
	{
		struct ip *iph = (struct ip*)(buffer + sizeof(struct ether_header));
		switch (iph->ip_p) //Check the Protocol and do accordingly...
		{
			case 6:  //TCP Protocol
				packet_info = tcp_packet(buffer, ipv6);
				break;
			 
			case 17: //UDP Protocol
				packet_info = udp_packet(buffer, ipv6);
				break;
		}
	}
	if (packet_info.header_size == -1){ // internal error
		exit(1);		 	 			//something went wrong (malloc, etc)
	}
	print_data(time, pkthdr->ts.tv_usec, packet_info, data_len, data);

    if (LOOPS > PNUM) { //not needed on mac, but needed for linux 
    	exit(0);
    }	
}

/*
*	Parses command line arguments
*	Loads value from arguments to program variables 
*	-h for help
*/
int args_parse(int argc, char *argv[], char *iface, char *port, int *pnum, int *tcp, int *udp)
{
	bool iface_bool = false;
	bool port_bool = false;
	static const struct option longopts[] = 
	{
		{.name = "tcp", .has_arg = no_argument, .val = 't'},
		{.name = "udp", .has_arg = no_argument, .val = 'u'},
		// {},
	};
	for (;;) 
	{
		int opt = getopt_long(argc, argv, "i:p:n:tuh", longopts, NULL);
		if (opt == -1){
			break; 
		}
		switch (opt) {
		case 'i':
			if (strlen(optarg) > 19)
			{
				fprintf(stderr, "Parameter for INTERFACE could not be longer than 9 characters!\n");
				return 1;
			}
			strcpy(iface, optarg);
			iface_bool = true;
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
			port_bool = true;
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
			puts("HELP:");
			puts("no parameters = lists all available interfaces");
			puts("-i <interface> interface, on which packet sniffer works");
			puts("-p <port_number> port on which we listen");
			puts("-t | --tcp shows only tcp packets");
			puts("-u | --udp shows only udp packets");
			puts("-n <packets_count> shows n packets (default is 1)");
			return 1;
		}
	}
	if (iface_bool == false ){	// interface was not specified
		return 33;
	}
	if (port_bool == false ){	// port was not specified
		return 44;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	char *iface = malloc(20 * sizeof(char));	//interface
	char *port = malloc(15 * sizeof(char));		//port
	if (iface == NULL || port == NULL) {
		return 1;
	}
	int pnum =0;	    	 			//number of packets
	int tcp = 0;	         			// tcp flag
	int udp = 0;			 			// udp flag
	char errbuf[PCAP_ERRBUF_SIZE]; 		//PCAP macro
	int args = 0;
	
	args = args_parse(argc, argv, iface, port, &pnum, &tcp, &udp);
	if (args == 1) {
		free(iface);
		free(port);
		return 1;		// when something went wrong
	}
	if (args == 33) {	// no command line arguments
		free(iface);
		free(port);
		iface = NULL;
	}
	if (args == 44) {	// no arguments with specified port
		free(port);
		port = NULL;
	}
	if (tcp == udp){
		tcp = udp = 0;	// that means it looks for both
	}
	if (pnum == 0) 		// default number
	{
		pnum = 1;
		PNUM = 1;
	}   
    else{
    	PNUM = pnum;
    }

	//when missing -i argument, it just list all possible interfaces
	if (iface == NULL)
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
		// date: 25th OCTOBER, 2012
		printf("Available interfaces:\n");
		for(dlist=alldevs; dlist; dlist=dlist->next)
		{
			printf("%dlist. %s", ++i, dlist->name);
			if (dlist->description)
				printf(" (%s)\n", dlist->description);
			else
				printf("(No description)\n");
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
	else if (udp == 1) {strcpy(filter, "udp ");}
	else if (port != NULL && (tcp == udp)) {strcpy(filter, port);}
	else if (port != NULL && (tcp != udp)) {strcat(filter, port);}
	else {strcpy(filter, "tcp or udp");}	// looks only for udp and tcp
	//source: https://www.tcpdump.org/manpages/pcap_compile.3pcap.html
	if(pcap_compile(opensniff, &fp, filter, 0, pNet) == -1)	
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

	if (iface != NULL){
		free(iface);
	}
	if (port != NULL){
		free(port);
	}

	return 0;
}



//////////////////////////////////////////////////////////////////
// 		CODES ABOVE ARE MOSTLY REFERENCED TO CODE BY Tim Carstens 
//	I have not actually taken anything from this code but they all
//	    		 are SOMEHOW CONNECTED TO THIS
//    		 	->	License listed below		 
//////////////////////////////////////////////////////////////////
/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 * http://www.tcpdump.org/sniffex.c?fbclid=IwAR0AXegTgHNW_-qiaeu5bsnrjf1COWRxQpjbgdIbn2ypljBD111fYY4BB88
 */
