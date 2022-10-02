#include <iostream>
#include <getopt.h>
#include <pcap/pcap.h>

// structure for program arguments
typedef struct {
	std::string file = ""; 			                // variable to store file name
	std::string collector = "127.0.0.1:2055";   // variable to store domane name for collector 
    int a_timer = 60; 			                // variable to store interval in seconds, netflow export
	int seconds = 10;           	            // variable to store interval in seconds
    int flow_cache = 1024;                      // variable to store flow cache size
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

void process_packet(u_char *args,const struct pcap_pkthdr *packet_header, const u_char* packet) {
	// need to be here to supress the warning
	(void)args;
	(void)packet;
	int len = (int)packet_header->len;
	std::cout << len << std::endl;
}


int main(int argc, char **argv){

    arguments_t args;
	pcap_t *handle; // Packet handle returned from pcap_open_offline
	//struct pcap_pkthdr header; // The header that pcap gives us 

    parse_arguments(argc, argv, &args);

	if (args.file != "") {
		// read from file
		handle = pcap_open_offline(args.file.c_str(), errbuf);
	} else {
		// read from stdin
		handle = pcap_open_offline("-", errbuf);
	}

	// main loop to read all packets from a pcap
	if (pcap_loop(handle, -1, process_packet, 0) == -1) {
		pcap_close(handle);
		my_exit("Pcap_loop failed", 1);
	}

	pcap_close(handle);
    return 0;
}