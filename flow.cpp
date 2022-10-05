#include <iostream>
#include <list>
#include <iterator>
#include <getopt.h>

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
	std::string file = ""; 			            // variable to store file name
	std::string collector = "127.0.0.1";   		// variable to store domane name for collector 
	unsigned int port = 2055;							// variable to store port number
    int a_timer = 60; 			                // variable to store interval in seconds, netflow export
	int seconds = 10;           	            // variable to store interval in seconds
    int flow_cache_size = 1024;                 // variable to store flow cache size
	int flow_seq;								// variable to store info about how many flows were seen
	std::list<nf_v5_body_t> flow_cache; 		// variable to represent the flow cache
	unsigned long currect_time;
	unsigned long first_packet_time;
} arguments_t;


char errbuf[PCAP_ERRBUF_SIZE];

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
			// TODO getaddrinfo or gethostbyname
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

// TODO use inet_pton
void parse_collector();

// TODO delete later
void print_flow(std::list<nf_v5_body_t> &flow_cache) {
	std::list<nf_v5_body_t>::iterator it;
	//std::cout << "src ip\tdst_ip\tsrc_port\tdst_port\tprotocol" << std::endl;
    for (it = flow_cache.begin(); it != flow_cache.end(); ++it) {
		std::cout << "bytes:\t" << it->num_bytes << " n_of_packet: " << it->num_packets << std::endl;
	}
	std::cout << "--------------------------------------------------\n";
	if (flow_cache.empty()) {
		std::cout << "flow cache is empty" << std::endl;
	}
}

// TODO prepare flow before I need to send it
u_char* prepare_flow(arguments_t* args, nf_v5_body_t flow_buff[], int n_of_flows) {

	nf_v5_header_t header = {};
	struct timeval tv = {};
	int err = 0;

	if ((err = gettimeofday(&tv, NULL)) == -1) {
		my_exit("gettimeofday() error", 1);
	}

	header.version = htons(5);
	header.count = htons(n_of_flows);
	header.sysuptime = htonl(args->currect_time - args->first_packet_time);
	header.unix_sec = tv.tv_sec;
	header.unix_nsecs = tv.tv_usec * 1000;
	header.flow_seq = htonl(args->flow_seq);
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

// TODO sent flow
void send_flow(arguments_t *args, nf_v5_body_t flow_buffer[], int n_of_flows) {
	std::cout << "Exporting " << n_of_flows << " flows" << std::endl;
	u_char *flow_to_export = prepare_flow(args, flow_buffer, n_of_flows);


	// TODO redo this
	// create UDP socket
	struct sockaddr_in servaddr;

	int sockfd = socket(AF_INET,SOCK_DGRAM,0);
	if (sockfd == -1) {
		my_exit("Socket failed to create", 1);
	}
	memset(&servaddr, 0, sizeof(servaddr)); 
	servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(args->port);
	servaddr.sin_addr.s_addr = inet_addr(args->collector.c_str());

	int err = sendto(sockfd, flow_to_export, 
					(sizeof(nf_v5_header_t) + sizeof(nf_v5_body_t)*n_of_flows),
					0,
					(struct sockaddr*) &servaddr,sizeof(struct sockaddr_in));
	if (err == -1) {
		my_exit("send to error",1);
	}

	args->flow_seq += n_of_flows;
	close(sockfd);
	free(flow_to_export);
}


int check_flow_exists(arguments_t* args, nf_v5_body_t *flow) {

	// check if flow is present
	std::list<nf_v5_body_t>::iterator it;
    for (it = args->flow_cache.begin(); it != args->flow_cache.end(); ++it) {
		if ((it->src_ip.s_addr == flow->src_ip.s_addr) && (it->dst_ip.s_addr == flow->dst_ip.s_addr)
			&& (it->src_port == flow->src_port) && (it->dst_port == flow->dst_port) &&
			(it->protocol == flow->protocol)) {
				// already in cache
				it->num_packets++;
				it->num_bytes += flow->num_bytes;
				it->tcp_flags |= flow->tcp_flags;
				it->last = args->currect_time - args->first_packet_time;
				return 0;
		}
	}


	// flow is not in the cache
	return 1;
}

void add_flow(arguments_t *args, nf_v5_body_t* flow) {

	// check if flow is full
	if (args->flow_cache.size() == (long unsigned int)args->flow_cache_size) {
		nf_v5_body_t flow_buff[30];
		flow_buff[0] = args->flow_cache.front();
		args->flow_cache.pop_front();
		send_flow(args, flow_buff, 1);
	}

	// flow is new so I set the number of packets to 1 and add the flow
	flow->num_packets = 1;
	flow->first = args->currect_time - args->first_packet_time;
	flow->last = args->currect_time - args->first_packet_time;
	args->flow_cache.push_back(*flow);
}


void process_flow(arguments_t *args, nf_v5_body_t *tmp_flow) {

	// TODO check inactive a active timer

	// check if flow is not in the cache then add it
	if (check_flow_exists(args, tmp_flow)) {
		add_flow(args, tmp_flow);
	}


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

	arguments_t *arg = (arguments_t*)args; //program arguments
	nf_v5_body_t flow_tmp = {}; // temporary flow that will be inicialized


	if (arg->first_packet_time == 0) {
		arg->first_packet_time = packet_header->ts.tv_sec * 1000 + packet_header->ts.tv_usec/1000;
	}
	arg->currect_time = packet_header->ts.tv_sec * 1000 + packet_header->ts.tv_usec/1000;

	eth_h = (struct ether_header*)(packet);
	ipv4_h = (struct ip*)(packet + ETHER_SIZE);
	udp_h = (struct udphdr*)(packet + ETHER_SIZE + ipv4_h->ip_hl*4);
	tcp_h = (struct tcphdr*)(packet + ETHER_SIZE + ipv4_h->ip_hl*4);

	// set information about flow that I can get from ip header
	flow_tmp.num_bytes = (int)packet_header->len - sizeof(struct ether_header);
	flow_tmp.src_ip = ipv4_h->ip_src;
	flow_tmp.dst_ip = ipv4_h->ip_dst;
	flow_tmp.tos = ipv4_h->ip_tos;

	// get info from corresponding header
	if (ntohs(eth_h->ether_type) == ETHERTYPE_IP) {

		if (ipv4_h->ip_p == TCP_PROTO_N) {
			// TCP
			get_tcp_info((u_char*)tcp_h, &flow_tmp);

		} else if (ipv4_h->ip_p == UDP_PROTO_N) {
			// UDP
			get_udp_info((u_char *)udp_h, &flow_tmp);

		} else if (ipv4_h->ip_p == ICMP_PROTO_N) {
			// ICMP
			flow_tmp.protocol = ICMP_PROTO_N;
	
		} else {
			std::cerr << "Something else than IPv4 was in the pcap file" << std::endl;
			return;
		}
		// all info about flow was retrieved now process_flow
		process_flow(arg, &flow_tmp);

	}
	//print_flow(arg->flow_cache);
}


int main(int argc, char **argv){

    arguments_t args = {};
	pcap_t *handle; // Packet handle returned from pcap_open_offline

    parse_arguments(argc, argv, &args);

	if (args.file != "") {
		// read from file
		handle = pcap_open_offline(args.file.c_str(), errbuf);
	} else {
		// read from stdin
		handle = pcap_open_offline("-", errbuf);
	}
	if (handle == NULL) {
		my_exit("Couldn't open file.",1);
	}

	// main loop to read all packets from a pcap
	if (pcap_loop(handle, -1, process_packet, (u_char*)&args) == -1) {
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
	//print_flow(args.flow_cache);
	
	pcap_close(handle);
    return 0;
}