#ifndef VIEW_HPP
#define VIEW_HPP

#include <vector>
#include <string>
#include <map>
#include "model.hpp"

class PortView {
public:
    void printAll(const std::vector<ConnectionInfo>& connections, bool show_process = true);
    
    void printListening(const std::vector<ConnectionInfo>& connections);
    
    void printTable(const std::vector<ConnectionInfo>& connections, 
                    const std::string& title = "TCP Connections");
    
    void printStatistics(const std::map<std::string, size_t>& stats);
    
    void printConnectionDetails(const ConnectionInfo& conn);
    
    void printCompact(const std::vector<ConnectionInfo>& connections);
    
private:
    std::string formatIp(const std::string& ip, bool is_ipv6);
    void printSeparator(char ch = '-', int length = 80);
};

#endif // VIEW_HPP