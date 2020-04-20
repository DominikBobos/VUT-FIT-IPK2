#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>


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
        	printf("Got i = %s\n", optarg);
        	strcpy(iface, optarg);
        	break;
        case 'p':
        	printf("Got p = %s\n", optarg);
        	*port = strtol(optarg, NULL, 10);
        	break;
        case 'n':
        	printf("Got n = %s\n", optarg);
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

	if (!args_parse(argc, argv, iface, &port, &pnum, &tcp, &udp))
		return 1;
	//printf("%s, %d, %d, %d, %d\n", iface, port, pnum, tcp, udp);
	if (tcp == udp)
		tcp = udp = 0;


	return 0;
}
