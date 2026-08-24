#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <vector>
#include <string>
#include <map>
#include <cstdint>
#include <chrono>
#include "model.hpp"

class PortScanner {
private:
    std::map<uint64_t, std::string> inode_to_process;
    std::chrono::steady_clock::time_point last_cache_update;
    bool cache_built;
    static constexpr int CACHE_TTL_SECONDS = 5;
    std::string hexToIp(const std::string& hex, bool is_ipv6 = false);
    uint16_t hexToPort(const std::string& hex);
    std::string stateToString(const std::string& hex);
    bool parseProcNetLine(const std::string& line, 
                          std::string& local_addr,
                          std::string& remote_addr,
                          std::string& state,
                          std::string& uid,
                          std::string& inode);
    
    void updateCacheForInodes(const std::vector<uint64_t>& inodes);
    std::vector<ConnectionInfo> parseProtocolFile(const std::string &path, bool is_ipv6);
    std::string findProcessByInode(uint64_t inode);
    bool isCacheStale() const;
    void buildProcessCache(); 
    
public:
    PortScanner();
    
    std::vector<ConnectionInfo> getAllTcpConnections(bool include_ipv6 = true);
    
    std::vector<ConnectionInfo> getListeningPorts(bool include_ipv6 = true);
    
    std::vector<ConnectionInfo> getConnectionsByState(const std::string& state, bool include_ipv6 = true);
    
    std::vector<ConnectionInfo> getConnectionsByUid(uint32_t uid, bool include_ipv6 = true);
    
    // Очистить кэш
    void clearCache() { 
        cache_built = false; 
        inode_to_process.clear(); 
    }
};

#endif // SCANNER_HPP