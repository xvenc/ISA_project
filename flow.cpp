#include <iostream>
#include <list>
#include <iterator>
#include <netinet/in.h>
#include <string>
#include <getopt.h>

#define __FAVOR_BSD

#include <pcap/pcap.h>
#include "netinet/ether.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "netinet/ip_icmp.h"
#include "netinet/tcp.h"
#include "netinet/udp.h"
#include "string.h"
#include "sys/time.h"
#include "sys/socket.h"
#include <unistd.h> 


#define ETHER_SIZE 14
#define TCP_PROTO_N 6
#define UDP_PROTO_N 17
#define ICMP_PROTO_N 1


typedef struct {
	uint16_t version;		// bytes 0-1
	uint16_t count; 		// bytes 2-3
	uint32_t sysuptime;		// bytes 4-7
	uint32_t unix_sec;		// bytes 8-11
	uint32_t unix_nsecs;	// bytes 12-15
	uint32_t flow_seq;		// bytes 16-19
	uint8_t engine_type;	// byte 20
	uint8_t engine_id;		// byte 21
	uint16_t sampling_int;	// bytes 22-23
}__attribute__((packed)) nf_v5_header_t;

typedef struct {
	struct in_addr src_ip;	// bytes 0-3
	struct in_addr dst_ip;	// bytes 4-7
	uint32_t next_hop;		// bytes 8-11
	uint16_t iif_index; 	// bytes 12-13
	uint16_t oif_index; 	// bytes 14-15
	uint32_t num_packets;	// bytes 16-19: Number of packets in the flow 
	uint32_t num_bytes;		// bytes 20-23: Number of bytes in the flow 
	uint32_t first;			// bytes 24-27: System uptime when flow started 
	uint32_t last;			// bytes 28-31: System uptime when flow ended 
	uint16_t src_port;      // bytes 32-33: Source port for tcp/udp/sctp flows.
	uint16_t dst_port;		// bytes 34-35: Destination port for tcp/udp/sctp flows.
	uint8_t  mid_pad;		// byte 36: zero pad 
	uint8_t  tcp_flags;		// byte 37: tcp flags or zero
	uint8_t  protocol;		// byte 38: IP protocol number
	uint8_t  tos;			// byte 39: IP Type of Service
	uint16_t src_as;      	// bytes 40-41: BGP source ASN
	uint16_t dst_as;   		// bytes 42-43: BGP destination ASN
	uint8_t  src_prefix;    // byte 44: number of bits in the source route mask 
	uint8_t  dst_prefix;    // byte 45: number of bites in the destination route mask 
	uint16_t end_pad;       // bytes 46-47: zero pad 
}__attribute__((packed)) nf_v5_body_t;

// structure for program arguments
typedef struct {
	std::string file = "-"; 			            // variable to store file name
	std::string collector = "127.0.0.1:2055";   // variable to store domane name for collector 
	u_int16_t port = 2055;							// variable to store port number
	int family;									// variable to IP adress family
    unsigned long a_timer = 60; 			    // variable to store interval in seconds, netflow export
	unsigned long seconds = 10;           	    // variable to store interval in seconds
    int flow_cache_size = 1024;                 // variable to store flow cache size
	int flow_seq;								// variable to store info about how many flows were seen
	std::list<nf_v5_body_t> flow_cache; 		// variable to represent the flow cache
	struct timeval currect_time; 				// store "current time" from pcap in milliseconds
	struct timeval first_packet_time;
	struct timeval ts;
} arguments_t;


char errbuf[PCAP_ERRBUF_SIZE];

static int counter;

// function that prints message to stderr and exits with given ret code
void my_exit(std::string msg, int ret_code) {
	std::cerr << msg << std::endl;
	exit(ret_code);
}


// function to parse all supported command line arguments
void parse_arguments(int argc, char** argv, arguments_t* args) {

	const char *short_opts = "f:c:a:i:m:";
	char *ptr;
	int c;

	while ((c = getopt(argc, argv,short_opts)) != -1){
		
		if (c == 'f') {
            args->file = optarg;   
			if (FILE *file = fopen(args->file.c_str(), "r")) {
				fclose(file);
			} else {
				my_exit("File doesn't exist\n", 1);
			}   
			
		} else if (c == 'c') {
            args->collector = optarg;

		} else if (c == 'a') {
            if (optarg[0] == '-') my_exit("Invalid argument", EXIT_FAILURE);
			
			args->a_timer = (u_int16_t)strtol(optarg,&ptr, 10);
			if (*ptr != '\0') {
				my_exit("Wrong active timer time\n",1);	
			}

        } else if (c == 'i') {
            if (optarg[0] == '-') my_exit("Invalid argument", EXIT_FAILURE);
			
			args->seconds = (u_int16_t)strtol(optarg,&ptr, 10);
			if (*ptr != '\0') {
				my_exit("Wrong inactive timer time\n",1);	
			}

        } else if (c == 'm') {
            if (optarg[0] == '-') my_exit("Invalid argument", EXIT_FAILURE);
			
			args->flow_cache_size = (u_int16_t)strtol(optarg,&ptr, 10);
			if (*ptr != '\0') {
				my_exit("Wrong flow-cache size\n",1);	
            }
	
        }else if (c == '?') my_exit("Wrong program argument\n", EXIT_FAILURE);

	}
}

u_int16_t check_port(std::string port) {
	char *ptr;
	int tmp = (u_int16_t)strtol(port.c_str(),&ptr, 10);
	if (*ptr != '\0') {
		my_exit("Wrong port number\n",1);	
	}
	if (tmp < 1 || tmp > 65535) my_exit("Wrong port number", EXIT_FAILURE);

	return tmp;
}

// TODO separate this
int parse_collector(arguments_t *args) {

	struct in_addr ipv4_addr;
	struct in6_addr ipv6_addr;
	struct addrinfo *result;
	int retval = 0;
	int valid_check = -1;
	std::string port = "";

	if ((retval = inet_pton(AF_INET, args->collector.c_str(), &ipv4_addr)) == 1) {
		// valid ipv4 with no port
		valid_check = args->family = AF_INET;
		return 0;
	
	} else if ((retval = inet_pton(AF_INET6, args->collector.c_str(), &ipv6_addr)) == 1) {
		// valid ipv6 with port
		valid_check = args->family = AF_INET6;
		return 0;
	}

	if (valid_check == -1) {
		size_t pos = args->collector.find_last_of(':');
		// ':' is in the string
		if (pos != std::string::npos) {
			port = args->collector.substr(pos + 1, args->collector.size()-1);	
			args->collector.erase(args->collector.begin()+pos,args->collector.end());
		}

		if (args->collector.find('[') != std::string::npos && args->collector.find(']') != std::string::npos) {
			// its ipv6 address with port number
			args->collector.erase(0,1);
			args->collector = args->collector.substr(0, args->collector.size()-1);
		}	
	}

	// try again
	if ((retval = inet_pton(AF_INET, args->collector.c_str(), &ipv4_addr)) == 1) {
		// valid ipv4 with port
		valid_check = args->family = AF_INET;
		args->port = check_port(port);
		return 0;
	
	} else if ((retval = inet_pton(AF_INET6, args->collector.c_str(), &ipv6_addr)) == 1) {
		// valid ipv6 with port
		valid_check = args->family = AF_INET6;
		args->port = check_port(port);
		return 0;
	}
	
	if (valid_check == -1) {
		// try host name
		if ((retval = getaddrinfo(args->collector.c_str(),NULL,NULL,&result)) == 0) {
			// valid hostname

			args->family = result->ai_addr->sa_family;
			if (args->family == AF_INET) {
				struct sockaddr_in *ipv4 = (struct sockaddr_in*)result->ai_addr;
				char *ip = (inet_ntoa(ipv4->sin_addr)); 
				std::string str(ip);
				args->collector = ip;
				args->port = check_port(port);

			} else {
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)result->ai_addr;
				char ipv6_ip[INET6_ADDRSTRLEN]; // constant taken from arpa/inet.h header file
				inet_ntop(AF_INET6, &ipv6->sin6_addr,ipv6_ip, INET6_ADDRSTRLEN);
				args->collector = ipv6_ip;
				args->port = check_port(port);
			}
			freeaddrinfo(result);
			return 0;
		}
	}
	// If i got here its not IPv4, IPv6 nor hostname
	return 1;
}

// get time of current packet since "boot time"
unsigned long get_time(struct timeval curr, struct timeval boot) {
	return (((curr.tv_sec - boot.tv_sec) * 1000) + (curr.tv_usec - boot.tv_usec)/1000);
}

// prepare flow before I need to send it
u_char* prepare_flow(arguments_t* args, nf_v5_body_t flow_buff[], int n_of_flows) {

	nf_v5_header_t header = {};
	header.version = htons(5);
	header.count = htons(n_of_flows);
	header.sysuptime = htonl((u_int32_t)get_time(args->currect_time, args->first_packet_time));
	header.unix_sec = htonl((u_int32_t)args->ts.tv_sec);
	header.unix_nsecs = htonl((u_int32_t)args->ts.tv_usec * 1000);
	header.flow_seq = htonl((u_int32_t)args->flow_seq);
	header.engine_type = 0;
	header.engine_id = 0;
	header.sampling_int = 0;


	for (int i = 0; i < n_of_flows; i++) {

		flow_buff[i].first = htonl(flow_buff[i].first);
		flow_buff[i].last = htonl(flow_buff[i].last);
		flow_buff[i].num_packets = htonl(flow_buff[i].num_packets);
		flow_buff[i].num_bytes = htonl(flow_buff[i].num_bytes);
  	}

	u_char *p = (u_char*)malloc(sizeof(nf_v5_header_t) + sizeof(nf_v5_body_t)*n_of_flows);

	if (p == NULL) {
		my_exit("Alloc failed", 1);
	}

	u_char *tmp = p;
	memcpy(p,&header,sizeof(nf_v5_header_t));

	for (int i = 0; i < n_of_flows; i++) {
		memcpy(tmp+sizeof(nf_v5_header_t)+sizeof(nf_v5_body_t)*i,&flow_buff[i], sizeof(nf_v5_body_t));
	}

	return p;
}

// sent flow
void send_flow(arguments_t *args, nf_v5_body_t flow_buffer[], int n_of_flows) {
	//std::cout << "Exporting " << n_of_flows << " flows. Packet number: " << counter << std::endl;
	u_char *flow_to_export = prepare_flow(args, flow_buffer, n_of_flows);


	// create UDP socket
	struct sockaddr_in servaddr;
	struct sockaddr_in6 serv6addr;
	int sockfd;
	int len = (sizeof(nf_v5_header_t) + sizeof(nf_v5_body_t)*n_of_flows);
	memset(&servaddr, 0, sizeof(servaddr)); 
	memset(&serv6addr,0,sizeof(serv6addr));

	if (args->family == AF_INET) {
		if ((sockfd = socket(AF_INET,SOCK_DGRAM,0)) == -1 ) {
			my_exit("Socket failed to create", 1);
		}
		servaddr.sin_family = args->family; 
		servaddr.sin_port = htons(args->port);
		inet_pton(AF_INET, args->collector.c_str(), &(servaddr.sin_addr));
		if (sendto(sockfd, flow_to_export, len,0,(struct sockaddr*) &servaddr,sizeof(struct sockaddr_in)) == -1) {
			my_exit("Sending error",1);
		}		

	} else {
		if ((sockfd = socket(AF_INET6,SOCK_DGRAM,0)) == -1 ) {
			my_exit("Socket failed to create", 1);
		}	
		serv6addr.sin6_family = args->family;
		serv6addr.sin6_port = htons(args->port);
		inet_pton(AF_INET6, args->collector.c_str(), &(serv6addr.sin6_addr));
		if (sendto(sockfd, flow_to_export, len,0,(struct sockaddr*) &serv6addr,sizeof(struct sockaddr_in6)) == -1) {
			my_exit("Sending to ipv6 error",1);
		}
	}
	args->flow_seq += n_of_flows;
	close(sockfd);
	free(flow_to_export);
}

// check if current new flow is already in flow cache
int check_flow_exists(arguments_t* args, nf_v5_body_t *flow) {

	// check if flow is present
	std::list<nf_v5_body_t>::iterator it;
    for (it = args->flow_cache.begin(); it != args->flow_cache.end(); ++it) {
		if ((it->src_ip.s_addr == flow->src_ip.s_addr) && (it->dst_ip.s_addr == flow->dst_ip.s_addr)
			&& (it->src_port == flow->src_port) && (it->dst_port == flow->dst_port) &&
			(it->protocol == flow->protocol) && (it->tos == flow->tos)) {
				// already in cache so update info about the cache
				it->num_packets++;
				it->num_bytes += flow->num_bytes;
				it->tcp_flags |= flow->tcp_flags;
				it->last = (u_int32_t)get_time(args->currect_time, args->first_packet_time);

				return 0;
		}
	}


	// flow is not in the cache
	return 1;
}

void add_flow(arguments_t *args, nf_v5_body_t* flow) {


	// check if flow is full
	if (args->flow_cache.size() == (long unsigned int)args->flow_cache_size) {
		//std::cout << "FULL cache ";
		nf_v5_body_t flow_buff[30];
		flow_buff[0] = args->flow_cache.front();
		args->flow_cache.pop_front();
		send_flow(args, flow_buff, 1);
	}

	// flow is new so I set the number of packets to 1 and add the flow
	//std::cout << "Add src: " << inet_ntoa(flow->src_ip) << "\tcounter: " << counter << std::endl;
	flow->num_packets = 1;
	flow->first = (u_int32_t)get_time(args->currect_time, args->first_packet_time);
	flow->last = (u_int32_t)get_time(args->currect_time, args->first_packet_time);
	args->flow_cache.push_back(*flow);

}

void check_timers(arguments_t *args) {

	std::list<nf_v5_body_t>::iterator i;
	int cnt = 0;
	nf_v5_body_t flow_buffer[30];

    for (i = args->flow_cache.begin(); i != args->flow_cache.end();) {
		unsigned long t = get_time(args->currect_time, args->first_packet_time);
		// active and inactive timers
		if (((t - i->first) >= (args->a_timer * 1000)) || ((t - i->last) >= (args->seconds*1000)) ) {
			//std::cout << "Timers expired" << std::endl;
			// store it
			flow_buffer[cnt++] = *i;
			i = args->flow_cache.erase(i);
			if (cnt == 30) {
				send_flow(args, flow_buffer, cnt);
				cnt = 0;
				memset(flow_buffer, 0, sizeof(flow_buffer));
			}
		} else {
			i++;
		}
	}
	// check if something remained unsend
	if (cnt != 0) { 
		//std::cout << "timers " ;
		send_flow(args, flow_buffer, cnt);
	}
}

// todo to count in the ack packet
void check_flags(arguments_t *args, nf_v5_body_t *flow) {
	std::list<nf_v5_body_t>::iterator i;
	nf_v5_body_t flow_buffer[30];
	int cnt = 0;
    for (i = args->flow_cache.begin(); i != args->flow_cache.end(); ++i) {
		// find the corresponding flow
		if ((i->src_ip.s_addr == flow->src_ip.s_addr) && (i->dst_ip.s_addr == flow->dst_ip.s_addr)
			&& (i->src_port == flow->src_port) && (i->dst_port == flow->dst_port) &&
			(i->protocol == flow->protocol) && (i->tos == flow->tos)) {
			// check if it has tcp fin or rst flags and then export it
			if (((i->tcp_flags & TH_FIN)) || (flow->tcp_flags & TH_RST)) {
				//(((i->tcp_flags & TH_FIN) && ((flow->tcp_flags & TH_ACK) && !(flow->tcp_flags & TH_FIN))))
				flow_buffer[cnt++] = *i;
				i = args->flow_cache.erase(i);
				send_flow(args, flow_buffer, cnt);	
				return;
			} 
		}
	}
}

void process_flow(arguments_t *args, nf_v5_body_t *tmp_flow) {

	// check inactive a active timer
	check_timers(args);	

	// check if flow is not in the cache then add it
	if (check_flow_exists(args, tmp_flow)) {
		add_flow(args, tmp_flow);
	}
	// check if current flow has tcp fin or rst flags
	// the flow was updated or added in the previous command
	check_flags(args, tmp_flow);
}

void get_tcp_info(const u_char *packet, nf_v5_body_t* tmp_flow) {

	struct tcphdr *tcp = (struct tcphdr*)(packet);
	tmp_flow->src_port = tcp->th_sport;
	tmp_flow->dst_port = tcp->th_dport;
	tmp_flow->protocol = TCP_PROTO_N;
	tmp_flow->tcp_flags = tcp->th_flags;

}

void get_udp_info(const u_char *packet, nf_v5_body_t* tmp_flow) {

	struct udphdr *udp_h = (struct udphdr*)(packet);
	tmp_flow->src_port = udp_h->uh_sport;
	tmp_flow->dst_port = udp_h->uh_dport;
	tmp_flow->protocol = UDP_PROTO_N;

}

void process_packet(u_char *args, const struct pcap_pkthdr *packet_header, const u_char* packet) {
	struct ether_header* eth_h; 		// structure for ethernet frame
	struct ip* ipv4_h; 					// struct for ipv4 frame
	struct udphdr *udp_h;
	struct tcphdr *tcp_h;
	struct icmp* icmp_h;

	arguments_t *arg = (arguments_t*)args; //program arguments
	nf_v5_body_t flow_tmp = {}; // temporary flow that will be inicialized

	eth_h = (struct ether_header*)(packet);
	ipv4_h = (struct ip*)(packet + ETHER_SIZE);
	udp_h = (struct udphdr*)(packet + ETHER_SIZE + ipv4_h->ip_hl*4);
	tcp_h = (struct tcphdr*)(packet + ETHER_SIZE + ipv4_h->ip_hl*4);
	icmp_h = (struct icmp*)(packet + ETHER_SIZE + ipv4_h->ip_hl * 4);

	// get info from corresponding header
	if (ntohs(eth_h->ether_type) == ETHERTYPE_IP) {
		counter++;

		if (arg->first_packet_time.tv_sec == 0 && arg->first_packet_time.tv_usec == 0) {

			arg->first_packet_time.tv_sec = packet_header->ts.tv_sec;
			arg->first_packet_time.tv_usec = packet_header->ts.tv_usec;
		}
		arg->currect_time.tv_sec = packet_header->ts.tv_sec;
		arg->currect_time.tv_usec = packet_header->ts.tv_usec;
		arg->ts.tv_sec = packet_header->ts.tv_sec;
		arg->ts.tv_usec = packet_header->ts.tv_usec;

		// set information about flow that I can get from ip header
		flow_tmp.num_bytes = (u_int32_t)(ntohs(ipv4_h->ip_len));
		flow_tmp.src_ip = ipv4_h->ip_src;
		flow_tmp.dst_ip = ipv4_h->ip_dst;
		flow_tmp.tos = ipv4_h->ip_tos;

		if (ipv4_h->ip_p == TCP_PROTO_N) {
			// TCP
			get_tcp_info((u_char*)tcp_h, &flow_tmp);

		} else if (ipv4_h->ip_p == UDP_PROTO_N) {
			// UDP
			get_udp_info((u_char *)udp_h, &flow_tmp);

		} else if (ipv4_h->ip_p == ICMP_PROTO_N) {
			// ICMP
			flow_tmp.protocol = ICMP_PROTO_N;
			flow_tmp.dst_port = icmp_h->icmp_type * 256 + icmp_h->icmp_code;
	
		} else return;

		// all info about flow was retrieved now process_flow
		process_flow(arg, &flow_tmp);

	} else {
		//std::cerr << "Unsupported protocol: Something else than IP is above ethernet header" << std::endl;
	}
}

int main(int argc, char **argv){

    arguments_t args = {};
	pcap_t *handle; // Packet handle returned from pcap_open_offline
	struct bpf_program packet_filter; 	// structure for compiled packet filter

    parse_arguments(argc, argv, &args);

	int ret = parse_collector(&args);
	if (ret != 0) {
		my_exit("invalid collector address", 1);
	}

	//std::cout << args.collector << " " << args.port << " " << args.family << std::endl;

	// read from file
	handle = pcap_open_offline(args.file.c_str(), errbuf);

	// check if file was opened right
	if (handle == NULL) {
		my_exit("Couldn't open file.",1);
	}

	// check if device provides ethernet headers
	if (pcap_datalink(handle) != DLT_EN10MB) {
		pcap_close(handle);
		my_exit("Device doesn't provide ethernet headers", 1);
	}

	// compile the created filter expression
	if (pcap_compile(handle, &packet_filter,"icmp or tcp or udp" , 0, PCAP_NETMASK_UNKNOWN) == -1) {
		pcap_close(handle);
		my_exit(pcap_geterr(handle), 1);
	}
	
	// apply the compiled filter
	if (pcap_setfilter(handle, &packet_filter) == -1) {
		pcap_close(handle);
		my_exit(pcap_geterr(handle), 1);
	}		

	// main loop to read all packets from a pcap
	if (pcap_loop(handle, -1, process_packet, (u_char*)&args) == -1) {
		pcap_freecode(&packet_filter);
		pcap_close(handle);
		my_exit("Pcap_loop failed", 1);
	}

	nf_v5_body_t flow_buffer[30];

	int i = 0;
	while (args.flow_cache.size() != 0) {
		flow_buffer[i++] = args.flow_cache.front();
		args.flow_cache.pop_front();
		if (i == 30) {
			send_flow(&args, flow_buffer, i);
			i = 0;
			memset(flow_buffer, 0, sizeof(flow_buffer));
		}
	}
	// check if something remained unsend
	if (i != 0) { 
		send_flow(&args, flow_buffer, i);
	}
	
	pcap_freecode(&packet_filter);
	pcap_close(handle);
    return 0;
}
