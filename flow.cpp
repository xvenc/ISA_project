#include <iostream>
#include <tuple>
#include <map>
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

#define ETHER_SIZE 14
#define TCP_PROTO_N 6
#define UDP_PROTO_N 17
#define ICMP_PROTO_N 1

// structure for program arguments
typedef struct {
	std::string file = ""; 			            // variable to store file name
	std::string collector = "127.0.0.1";   		// variable to store domane name for collector 
	int port = 2055;							// variable to store port number
    int a_timer = 60; 			                // variable to store interval in seconds, netflow export
	int seconds = 10;           	            // variable to store interval in seconds
    int flow_cache = 1024;                      // variable to store flow cache size
} arguments_t;


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

typedef struct {
	nf_v5_header_t header;
	nf_v5_body_t body;

} nf_v5_packet_t;

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
			
			args->flow_cache = (u_int16_t)strtol(optarg,&ptr, 10);
			if (*ptr != '\0') {
				my_exit("Wrong flow-cache size\n",1);	
            }
	
        }else if (c == '?') my_exit("Wrong program argument\n", EXIT_FAILURE);

	}
}


void print_flow(std::list<nf_v5_packet_t> &flow_cache) {
	std::list<nf_v5_packet_t>::iterator it;
	//std::cout << "src ip\tdst_ip\tsrc_port\tdst_port\tprotocol" << std::endl;
    for (it = flow_cache.begin(); it != flow_cache.end(); ++it) {
		std::cout << "bytes:\t" << it->body.num_bytes << " n_of_packet: " << it->body.num_packets << std::endl;
	}
	std::cout << "--------------------------------------------------\n";
}

void check_flow(std::list<nf_v5_packet_t> &flow_cache, nf_v5_packet_t flow) {

	std::list<nf_v5_packet_t>::iterator it;
    for (it = flow_cache.begin(); it != flow_cache.end(); ++it) {
		if ((it->body.src_ip.s_addr == flow.body.src_ip.s_addr) && (it->body.dst_ip.s_addr == flow.body.dst_ip.s_addr)
			&& (it->body.src_port == flow.body.src_port) && (it->body.dst_port == flow.body.dst_port) &&
			(it->body.protocol == flow.body.protocol)) {
				// already in cache
				it->body.num_packets++;
				it->body.num_bytes += flow.body.num_bytes;
				it->body.tcp_flags |= flow.body.tcp_flags;
				return;
		}
	}
	// flow is new so I set the number of packets to 1
	flow.body.num_packets = 1;
	flow_cache.push_back(flow);
	return;
}

// TODO create flow header when I need to send the packet
void create_flow_header();

// TODO sent flow

void send_flow();

void process_tcp(const u_char *packet, std::list<nf_v5_packet_t> &flow_cache, nf_v5_packet_t* tmp_flow) {
	struct ip *ipv4_h = (struct ip*)(packet + ETHER_SIZE);
	struct tcphdr *tcp = (struct tcphdr*)(packet + ETHER_SIZE + ipv4_h->ip_hl*4);
	tmp_flow->body.src_port = tcp->th_sport;
	tmp_flow->body.dst_port = tcp->th_dport;
	tmp_flow->body.protocol = TCP_PROTO_N;
	tmp_flow->body.tcp_flags = tcp->th_flags;
	check_flow(flow_cache, *tmp_flow);

}

void process_udp(const u_char *packet, std::list<nf_v5_packet_t> &flow_cache, nf_v5_packet_t* tmp_flow) {

	struct ip *ipv4_h = (struct ip*)(packet + ETHER_SIZE);
	struct udphdr *udp_h = (struct udphdr*)(packet + ETHER_SIZE + ipv4_h->ip_hl*4);
	tmp_flow->body.src_port = udp_h->uh_sport;
	tmp_flow->body.dst_port = udp_h->uh_dport;
	tmp_flow->body.protocol = UDP_PROTO_N;
	check_flow(flow_cache, *tmp_flow);

}

void process_icmp(std::list<nf_v5_packet_t> &flow_cache, nf_v5_packet_t* tmp_flow) {

	tmp_flow->body.protocol = ICMP_PROTO_N;
	check_flow(flow_cache, *tmp_flow);

}

void process_packet(u_char *args, const struct pcap_pkthdr *packet_header, const u_char* packet) {
	struct ether_header* eth_h; 		// structure for ethernet frame
	struct ip* ipv4_h; 					// struct for ipv4 frame

	static std::list<nf_v5_packet_t> flow_cache; //flow_cache
	arguments_t *arguments = (arguments_t*)args; //program arguments
	nf_v5_packet_t flow_tmp = {}; // temporary flow that will be inicialized
	
	eth_h = (struct ether_header*)(packet);
	ipv4_h = (struct ip*)(packet + ETHER_SIZE);

	// set information about flow that I can get from ip header
	flow_tmp.body.num_bytes = (int)packet_header->len - sizeof(struct ether_header);
	flow_tmp.body.src_ip = ipv4_h->ip_src;
	flow_tmp.body.dst_ip = ipv4_h->ip_dst;
	flow_tmp.body.tos = ipv4_h->ip_tos;
	// TODO first and last time of packet of the flow

	if (ntohs(eth_h->ether_type) == ETHERTYPE_IP) {

		if (ipv4_h->ip_p == TCP_PROTO_N) {
			// TCP
			process_tcp(packet, flow_cache, &flow_tmp);
			//std::cout << "TCP " << flow_cache.size() << std::endl;
		} else if (ipv4_h->ip_p == UDP_PROTO_N) {
			// UDP
			process_udp(packet, flow_cache, &flow_tmp);
			//std::cout << "UDP " << flow_cache.size() << std::endl;

		} else if (ipv4_h->ip_p == ICMP_PROTO_N) {
			process_icmp(flow_cache, &flow_tmp);
			//std::cout << "ICMP " << flow_cache.size() << std::endl;
	
		} else {
			std::cerr << "Something else than IPv4 was in the pcap file" << std::endl;
		}
	}

	//print_flow(flow_cache);
}


int main(int argc, char **argv){

    arguments_t args;
	pcap_t *handle; // Packet handle returned from pcap_open_offline

	// TODO add filter
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

	pcap_close(handle);
    return 0;
}