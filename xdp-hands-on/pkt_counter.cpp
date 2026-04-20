#include <iostream>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/libxdp.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <interface> <object_file>" << std::endl;
        return EXIT_FAILURE;
    }

    const char* ifname = argv[1];
    const char* obj_file = argv[2];

    struct xdp_program *prog = xdp_program__open_file(obj_file, "xdp", nullptr);
    if (libxdp_get_error(prog)) {
        std::cerr << "Failed to open XDP program from file: " << obj_file << std::endl;
        return EXIT_FAILURE;        
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        std::cerr << "Failed to get ifindex for interface: " << ifname << std::endl;
        return EXIT_FAILURE;        
    }

    auto ret = xdp_program__attach(prog, ifindex, XDP_MODE_NATIVE, 0 );

    if (ret) {
        std::cerr << "Failed to attach XDP program to interface: " << ifname << std::endl;
        return EXIT_FAILURE;        
    }   

    std::cout << "XDP program successfully attached to interface: " << ifname << std::endl;

    auto bpf_obj = xdp_program__bpf_obj(prog);
    if (libxdp_get_error(bpf_obj)) {
        std::cerr << "Failed to get bpf object from XDP program" << std::endl;
        return EXIT_FAILURE;        
    }

    // Get the map id for the map named "rxcnt"
    int map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "rxcnt");
    
    if (map_fd < 0) {
        std::cerr << "Failed to get map fd for map named rxcnt" << std::endl;
        return EXIT_FAILURE;       
    }

    
  //  for (;;) {
  //      __u32 key = 0;
  //      __u64 value;

  //      if (bpf_map_lookup_elem(map_fd, &key, &value) == 0 ) {
  //          std::cout << "Counter for key " << key << ": " << value << std::endl;
  //      } else {
  //          std::cerr << "Failed to lookup element for key " << key << std::endl;   
  //      }

  //      key = 1;
  //      if (bpf_map_lookup_elem(map_fd, &key, &value) == 0 ) {
  //          std::cout << "Counter for key " << key << ": " << value << std::endl;
  //      } else {
  //          std::cerr << "Failed to lookup element for key " << key << std::endl;   
  //      }

  //      std::cout << "-----------------------------" << std::endl;

  //      sleep(  1);
  //  }



}