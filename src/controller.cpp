#include "controller.hpp"
#include <algorithm>
#include <map>

PortController::PortController() {
    refresh();
}

void PortController::refresh(bool include_ipv6) {
    current_connections = scanner.getAllTcpConnections(include_ipv6);
}

const std::vector<ConnectionInfo>& PortController::getAll() const {
    return current_connections;
}

std::vector<ConnectionInfo> PortController::getListening() const {
    std::vector<ConnectionInfo> result;
    for (const auto& conn : current_connections) {
        if (conn.state == "LISTEN") {
            result.push_back(conn);
        }
    }
    return result;
}

std::vector<ConnectionInfo> PortController::getByState(const std::string& state) const {
    std::vector<ConnectionInfo> result;
    for (const auto& conn : current_connections) {
        if (conn.state == state) {
            result.push_back(conn);
        }
    }
    return result;
}

std::vector<ConnectionInfo> PortController::getByUid(uint32_t uid) const {
    std::vector<ConnectionInfo> result;
    for (const auto& conn : current_connections) {
        if (conn.uid == uid) {
            result.push_back(conn);
        }
    }
    return result;
}

std::vector<ConnectionInfo> PortController::getByProcess(const std::string& process_name) const {
    std::vector<ConnectionInfo> result;
    for (const auto& conn : current_connections) {
        if (conn.process_name == process_name) {
            result.push_back(conn);
        }
    }
    return result;
}

ConnectionInfo PortController::findPort(uint16_t port) const {
    for (const auto& conn : current_connections) {
        if (conn.port == port) {
            return conn;
        }
    }
    return ConnectionInfo(); // empty/default ConnectionInfo if not found
}

size_t PortController::countByState(const std::string& state) const {
    size_t count = 0;
    for (const auto& conn : current_connections) {
        if (conn.state == state) {
            count++;
        }
    }
    return count;
}

std::map<std::string, size_t> PortController::getStateStatistics() const {
    std::map<std::string, size_t> stats;
    for (const auto& conn : current_connections) {
        stats[conn.state]++;
    }
    return stats;
}