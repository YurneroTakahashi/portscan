#ifndef MODEL_HPP
#define MODEL_HPP

#include <string>
#include <cstdint>

struct ConnectionInfo {
    uint16_t port;
    std::string local_ip;
    std::string state;
    uint32_t uid;
    uint64_t inode;
    std::string process_name;
    bool is_ipv6;
    
    ConnectionInfo() 
        : port(0), uid(0), inode(0), is_ipv6(false) {}
    
    ConnectionInfo(uint16_t p, const std::string& ip, const std::string& st, 
                   uint32_t u, uint64_t inode_id, const std::string& proc = "unknown", bool ipv6 = false)
        : port(p), local_ip(ip), state(st), uid(u), inode(inode_id), 
          process_name(proc), is_ipv6(ipv6) {}
};

#endif // MODEL_HPP