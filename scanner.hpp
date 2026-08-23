#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include "model.hpp"

class PortScanner {
private:
    std::map<uint64_t, std::string> inode_to_process;
    bool cache_built;
    
    // Additional parser methods
    std::string hexToIp(const std::string& hex, bool is_ipv6 = false);
    uint16_t hexToPort(const std::string& hex);
    std::string stateToString(const std::string& hex);
    
    // (scanning /proc/[pid]/fd)
    std::string findProcessByInode(uint64_t inode);
    void buildProcessCache();
    
    std::vector<ConnectionInfo> parseProtocolFile(const std::string& path, bool is_ipv6);
    
public:
    PortScanner();
    
    std::vector<ConnectionInfo> getAllTcpConnections(bool include_ipv6 = true);
    
    std::vector<ConnectionInfo> getListeningPorts(bool include_ipv6 = true);
    
    std::vector<ConnectionInfo> getConnectionsByState(const std::string& state, bool include_ipv6 = true);
    
    std::vector<ConnectionInfo> getConnectionsByUid(uint32_t uid, bool include_ipv6 = true);
    
    void clearCache() { cache_built = false; inode_to_process.clear(); }
};

#endif // SCANNER_HPP