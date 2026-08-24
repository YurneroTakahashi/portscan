#include "view.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <algorithm>

void PortView::printSeparator(char ch, unsigned int length) {
    std::cout << std::string(length, ch) << "\n";
}

std::string PortView::formatIp(const std::string& ip, bool is_ipv6) {
    if (is_ipv6) {
        return "[" + ip + "]";
    }
    return ip;
}

void PortView::printTable(const std::vector<ConnectionInfo>& connections, 
                          const std::string& title) {
    if (connections.empty()) {
        std::cout << "\033[1;33mNo connections found.\033[0m\n";
        return;
    }
    
    std::cout << "\n\033[1;36m=== " << title << " ===\033[0m\n";
    printSeparator('=');
    
    // cOlOrFuL HeAdEr
    std::cout << std::left 
              << "\033[1;37m"
              << std::setw(25) << "Local IP"
              << std::setw(10) << "Port"
              << std::setw(14) << "State"
              << std::setw(8) << "UID"
              << std::setw(12) << "Inode"
              << std::setw(20) << "Process"
              << std::setw(8) << "IPv6"
              << "\033[0m"
              << "\n";
    printSeparator('-');
    
    // cOlOrFuL dAtA
    for (const auto& conn : connections) {
        // color
        std::string color;
        if (conn.state == "LISTEN") {
            color = "\033[1;32m";  // green for LISTEN
        } else if (conn.state == "ESTABLISHED") {
            color = "\033[1;34m";  // blue for ESTABLISHED
        } else if (conn.state == "TIME_WAIT") {
            color = "\033[1;33m";  // yellow for TIME_WAIT
        } else {
            color = "\033[0m";     // defaulto
        }
        
        std::cout << color
                  << std::left
                  << std::setw(25) << conn.local_ip
                  << std::setw(10) << conn.port
                  << std::setw(14) << conn.state
                  << std::setw(8) << conn.uid
                  << std::setw(12) << conn.inode
                  << std::setw(20) << conn.process_name
                  << std::setw(8) << (conn.is_ipv6 ? "yes" : "no")
                  << "\033[0m"
                  << "\n";
    }
    printSeparator('-');
    std::cout << "Total: " << connections.size() << " connections\n";
}

void PortView::printAll(const std::vector<ConnectionInfo>& connections) {
    printTable(connections, "All TCP Connections");
}

void PortView::printListening(const std::vector<ConnectionInfo>& connections) {
    printTable(connections, "Listening Ports");
}

void PortView::printCompact(const std::vector<ConnectionInfo>& connections) {
    if (connections.empty()) {
        std::cout << "No connections\n";
        return;
    }
    
    std::cout << "\nPort  Process      State\n";
    printSeparator('-', 40);
    
    for (const auto& conn : connections) {
        std::cout << std::left
                  << std::setw(6) << conn.port
                  << std::setw(12) << conn.process_name
                  << conn.state << "\n";
    }
}

void PortView::printStatistics(const std::map<std::string, size_t>& stats) {
    std::cout << "\n=== Connection Statistics ===\n";
    printSeparator('-');
    
    size_t total = 0;
    for (const auto& [state, count] : stats) {
        std::cout << std::left << std::setw(14) << state << ": " << count << "\n";
        total += count;
    }
    printSeparator('-');
    std::cout << "Total: " << total << "\n";
}

void PortView::printConnectionDetails(const ConnectionInfo& conn) {
    std::cout << "\n=== Connection Details ===\n";
    printSeparator('-');
    std::cout << "Port:        " << conn.port << "\n";
    std::cout << "IP Address:  " << conn.local_ip << "\n";
    std::cout << "State:       " << conn.state << "\n";
    std::cout << "UID:         " << conn.uid << "\n";
    std::cout << "Inode:       " << conn.inode << "\n";
    std::cout << "Process:     " << conn.process_name << "\n";
    std::cout << "IPv6:        " << (conn.is_ipv6 ? "yes" : "no") << "\n";
}
