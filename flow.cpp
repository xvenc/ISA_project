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
			
		} else if (c == 'c') {
            args->collector = optarg;

		} else if (c == 'a') {
            if (optarg[0] == '-') my_exit("Invalid argument", EXIT_FAILURE);
			
			args->a_timer = (u_int16_t)strtol(optarg,&ptr, 10);
			if (*ptr != '\0') {
				my_exit("Wrong port number\n",1);	
			}

        } else if (c == 'i') {
            if (optarg[0] == '-') my_exit("Invalid argument", EXIT_FAILURE);
			
			args->seconds = (u_int16_t)strtol(optarg,&ptr, 10);
			if (*ptr != '\0') {
				my_exit("Wrong port number\n",1);	
			}

        } else if (c == 'm') {
            if (optarg[0] == '-') my_exit("Invalid argument", EXIT_FAILURE);
			
			args->flow_cache = (u_int16_t)strtol(optarg,&ptr, 10);
			if (*ptr != '\0') {
				my_exit("Wrong port number\n",1);	
            }
	
        }else if (c == '?') my_exit("Wrong program argument\n", EXIT_FAILURE);

	}
}


int main(int argc, char **argv){

    arguments_t args;
    parse_arguments(argc, argv, &args);
//    std::cout << "FILE: " + args.file << std::endl;
//    std::cout << "Colector: " + args.collector << std::endl;
//    std::cout << "active: " << args.a_timer << std::endl;
//    std::cout << "seconds: " << args.seconds << std::endl;
//    std::cout << "count: " << args.flow_cache << std::endl;

    return 0;
}