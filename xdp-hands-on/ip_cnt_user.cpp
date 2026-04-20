#include <cstdlib>
#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char* argv[]) {

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <map_id>" << std::endl;
        return EXIT_FAILURE;
    }

    int map_id = std::atoi(argv[1]);
    int map_fd = bpf_map_get_fd_by_id(map_id);
    if (map_fd < 0) {
        std::cerr << "Failed to get map fd for map id " << map_id << std::endl;
        return EXIT_FAILURE;
    }

    // Read and print the counters for ipv4 and non ipv4 packets

    for (;;) {
        __u32 key = 0;
        __u64 value;

        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0 ) {
            std::cout << "Counter for key " << key << ": " << value << std::endl;
        } else {
            std::cerr << "Failed to lookup element for key " << key << std::endl;   
        }

        key = 1;
        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0 ) {
            std::cout << "Counter for key " << key << ": " << value << std::endl;
        } else {
            std::cerr << "Failed to lookup element for key " << key << std::endl;   
        }

        std::cout << "-----------------------------" << std::endl;

        sleep(  1);
    }



    return EXIT_SUCCESS;
}