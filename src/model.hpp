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

struct RawConnection {
    std::string local_addr;
    std::string remote_addr;
    std::string state_hex;    // сырое значение состояния (например, "0A")
    std::string uid;
    std::string inode_str;
    std::string ip_hex;
    std::string port_hex;
    uint16_t port;
    bool is_ipv6;
    uint64_t inode;
    
    RawConnection() : port(0), is_ipv6(false), inode(0) {}
};


#endif // MODEL_HPP