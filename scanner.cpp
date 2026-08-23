#include "scanner.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <dirent.h>
#include <unistd.h>
#include <cstring>
#include <cctype>
#include <algorithm>

PortScanner::PortScanner() : cache_built(false) {}

std::string PortScanner::hexToIp(const std::string& hex, bool is_ipv6) {
    if (is_ipv6) {
        // IPv6: 32 symbols in hex
        if (hex.length() != 32) return "invalid";
        
        std::string ipv6;
        for (size_t i = 0; i < 32; i += 4) {
            if (i > 0) ipv6 += ':';
            ipv6 += hex.substr(i, 4);
        }
        return ipv6;
    }
    
    // IPv4: 8 symbols in hex (little-endian)
    if (hex.length() != 8) return "invalid";
    
    try {
        uint32_t ip = std::stoul(hex, nullptr, 16);
        unsigned char bytes[4];
        bytes[0] = (ip >> 0) & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        
        std::ostringstream oss;
        oss << (int)bytes[0] << "." << (int)bytes[1] << "." 
            << (int)bytes[2] << "." << (int)bytes[3];
        return oss.str();
    } catch (...) {
        return "invalid";
    }
}

uint16_t PortScanner::hexToPort(const std::string& hex) {
    try {
        return std::stoul(hex, nullptr, 16);
    } catch (...) {
        return 0;
    }
}

std::string PortScanner::stateToString(const std::string& hex) {
    try {
        int state = std::stoul(hex, nullptr, 16);
        switch(state) {
            case 0x01: return "ESTABLISHED";
            case 0x02: return "SYN_SENT";
            case 0x03: return "SYN_RECV";
            case 0x04: return "FIN_WAIT1";
            case 0x05: return "FIN_WAIT2";
            case 0x06: return "TIME_WAIT";
            case 0x07: return "CLOSE";
            case 0x08: return "CLOSE_WAIT";
            case 0x09: return "LAST_ACK";
            case 0x0A: return "LISTEN";
            case 0x0B: return "CLOSING";
            default: return "UNKNOWN";
        }
    } catch (...) {
        return "UNKNOWN";
    }
}

std::string PortScanner::findProcessByInode(uint64_t inode) {
    // cache-first
    if (cache_built) {
        auto it = inode_to_process.find(inode);
        if (it != inode_to_process.end()) {
            return it->second;
        }
        return "unknown";
    }
    
    // scan the /proc/[pid]/fd
    DIR* proc = opendir("/proc");
    if (!proc) return "unknown";
    
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        if (!isdigit(entry->d_name[0])) continue;
        
        std::string pid = entry->d_name;
        std::string fd_path = "/proc/" + pid + "/fd";
        
        DIR* fd_dir = opendir(fd_path.c_str());
        if (!fd_dir) continue;
        
        struct dirent* fd_entry;
        while ((fd_entry = readdir(fd_dir)) != nullptr) {
            if (fd_entry->d_name[0] == '.') continue;
            
            std::string link_path = fd_path + "/" + fd_entry->d_name;
            char buf[256];
            ssize_t len = readlink(link_path.c_str(), buf, sizeof(buf)-1);
            
            if (len > 0) {
                buf[len] = '\0';
                std::string link(buf);
                
                // look for "socket:[inode]"
                std::string socket_pattern = "socket:[" + std::to_string(inode) + "]";
                if (link.find(socket_pattern) != std::string::npos) {
                    // process name
                    std::string comm_path = "/proc/" + pid + "/comm";
                    std::ifstream comm_file(comm_path);
                    std::string comm;
                    if (std::getline(comm_file, comm)) {
                        if (!comm.empty() && comm.back() == '\n') {
                            comm.pop_back();
                        }
                        closedir(fd_dir);
                        closedir(proc);
                        return comm;
                    }
                }
            }
        }
        closedir(fd_dir);
    }
    closedir(proc);
    return "unknown";
}

void PortScanner::buildProcessCache() {
    if (cache_built) return;
    
    inode_to_process.clear();
    
    DIR* proc = opendir("/proc");
    if (!proc) return;
    
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        if (!isdigit(entry->d_name[0])) continue;
        
        std::string pid = entry->d_name;
        std::string fd_path = "/proc/" + pid + "/fd";
        
        DIR* fd_dir = opendir(fd_path.c_str());
        if (!fd_dir) continue;

        std::string comm_path = "/proc/" + pid + "/comm";
        std::ifstream comm_file(comm_path);
        std::string comm;
        if (std::getline(comm_file, comm)) {
            if (!comm.empty() && comm.back() == '\n') {
                comm.pop_back();
            }
        } else {
            comm = "unknown";
        }
        
        struct dirent* fd_entry;
        while ((fd_entry = readdir(fd_dir)) != nullptr) {
            if (fd_entry->d_name[0] == '.') continue;
            
            std::string link_path = fd_path + "/" + fd_entry->d_name;
            char buf[256];
            ssize_t len = readlink(link_path.c_str(), buf, sizeof(buf)-1);
            
            if (len > 0) {
                buf[len] = '\0';
                std::string link(buf);
                
                // look for socket:[inode]
                size_t start = link.find("socket:[");
                if (start != std::string::npos) {
                    size_t end = link.find(']', start);
                    if (end != std::string::npos) {
                        std::string inode_str = link.substr(start + 8, end - start - 8);
                        try {
                            uint64_t inode_num = std::stoull(inode_str);
                            inode_to_process[inode_num] = comm;
                        } catch (...) {}
                    }
                }
            }
        }
        closedir(fd_dir);
    }
    closedir(proc);
    cache_built = true;
}

std::vector<ConnectionInfo> PortScanner::parseProtocolFile(const std::string& path, bool is_ipv6) {
    std::vector<ConnectionInfo> connections;
    std::ifstream file(path);
    
    if (!file.is_open()) {
        std::cerr << "Warning: Cannot open " << path << std::endl;
        return connections;
    }

    if (!cache_built) {
        buildProcessCache();
    }
    
    std::string line;
    bool is_header = true;
    
    while (std::getline(file, line)) {
        if (is_header) {
            is_header = false;
            continue;
        }
        
        if (line.empty()) continue;
        
        std::istringstream iss(line);
        std::string sl, local_addr, remote_addr, st, tx_queue, rx_queue;
        std::string tr, tm, retrnsmt, uid, timeout, inode;
        
        if (!(iss >> sl >> local_addr >> remote_addr >> st >> tx_queue >> rx_queue 
              >> tr >> tm >> retrnsmt >> uid >> timeout >> inode)) {
            continue;
        }
        
        // DEMOLISH THE HELL OUT OF local_address:port
        size_t colon_pos = local_addr.find(':');
        if (colon_pos == std::string::npos) continue;
        
        std::string ip_hex = local_addr.substr(0, colon_pos);
        std::string port_hex = local_addr.substr(colon_pos + 1);
        
        if (is_ipv6 && ip_hex.length() != 32) continue;
        if (!is_ipv6 && ip_hex.length() != 8) continue;
        
        uint16_t port = hexToPort(port_hex);
        if (port == 0) continue;
        
        std::string ip = hexToIp(ip_hex, is_ipv6);
        std::string state = stateToString(st);
        
        uint32_t uid_num = 0;
        try {
            uid_num = std::stoul(uid);
        } catch (...) {}
        
        uint64_t inode_num = 0;
        try {
            inode_num = std::stoull(inode);
        } catch (...) {}
        
        // get process name via cache
        std::string process = "unknown";
        auto it = inode_to_process.find(inode_num);
        if (it != inode_to_process.end()) {
            process = it->second;
        }
        
        connections.emplace_back(port, ip, state, uid_num, inode_num, process, is_ipv6);
    }
    
    file.close();
    return connections;
}

std::vector<ConnectionInfo> PortScanner::getAllTcpConnections(bool include_ipv6) {
    std::vector<ConnectionInfo> all;
    
    auto tcp4 = parseProtocolFile("/proc/net/tcp", false);
    all.insert(all.end(), tcp4.begin(), tcp4.end());
    
    if (include_ipv6) {
        auto tcp6 = parseProtocolFile("/proc/net/tcp6", true);
        all.insert(all.end(), tcp6.begin(), tcp6.end());
    }
    
    return all;
}

std::vector<ConnectionInfo> PortScanner::getListeningPorts(bool include_ipv6) {
    auto all = getAllTcpConnections(include_ipv6);
    std::vector<ConnectionInfo> listening;
    
    for (const auto& conn : all) {
        if (conn.state == "LISTEN") {
            listening.push_back(conn);
        }
    }
    
    return listening;
}

std::vector<ConnectionInfo> PortScanner::getConnectionsByState(const std::string& state, bool include_ipv6) {
    auto all = getAllTcpConnections(include_ipv6);
    std::vector<ConnectionInfo> filtered;
    
    for (const auto& conn : all) {
        if (conn.state == state) {
            filtered.push_back(conn);
        }
    }
    
    return filtered;
}

std::vector<ConnectionInfo> PortScanner::getConnectionsByUid(uint32_t uid, bool include_ipv6) {
    auto all = getAllTcpConnections(include_ipv6);
    std::vector<ConnectionInfo> filtered;
    
    for (const auto& conn : all) {
        if (conn.uid == uid) {
            filtered.push_back(conn);
        }
    }
    
    return filtered;
}