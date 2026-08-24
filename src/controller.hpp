#ifndef CONTROLLER_HPP
#define CONTROLLER_HPP

#include <vector>
#include <string>
#include "model.hpp"
#include "scanner.hpp"

class PortController {
private:
    PortScanner scanner;
    std::vector<ConnectionInfo> current_connections;
    
public:
    PortController();
    
    void refresh(bool include_ipv6 = true);


    const std::vector<ConnectionInfo>& getAll() const;
    
    std::vector<ConnectionInfo> getListening() const;
    
    std::vector<ConnectionInfo> getByState(const std::string& state) const;
    
    std::vector<ConnectionInfo> getByUid(uint32_t uid) const;
    
    std::vector<ConnectionInfo> getByProcess(const std::string& process_name) const;
    
    ConnectionInfo findPort(uint16_t port) const;
    
    size_t countByState(const std::string& state) const;
    std::map<std::string, size_t> getStateStatistics() const;
};

#endif // CONTROLLER_HPP