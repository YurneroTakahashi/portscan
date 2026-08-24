#include "controller.hpp"
#include "view.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <csignal>
#include <chrono>
#include <thread>
#include <iomanip>
#include <getopt.h>
#include <algorithm>

std::atomic<bool> running{true};

void signalHandler(int signal) {
    if (signal == SIGINT) {
        running = false;
    }
}

struct ProgramArgs {
    bool watch_mode = false;
    int interval_seconds = 2;
    bool show_help = false;
    bool show_listening_only = false;
    bool show_statistics = false;
    bool show_compact = false;
    bool show_ipv6 = true;
    int filter_port = 0;
    std::string filter_process;
};

ProgramArgs parseArguments(int argc, char* argv[]) {
    ProgramArgs args;
    
    // getopt_long options
    static struct option long_options[] = {
        {"watch",      no_argument,       0, 'w'},
        {"interval",   required_argument, 0, 'i'},
        {"help",       no_argument,       0, 'h'},
        {"listening",  no_argument,       0, 'l'},
        {"stats",      no_argument,       0, 's'},
        {"compact",    no_argument,       0, 'c'},
        {"ipv4-only",  no_argument,       0, '4'},
        {"port",       required_argument, 0, 'p'},
        {"process",    required_argument, 0, 'P'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "wi:hlsc4p:P:", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'w':
                args.watch_mode = true;
                break;
            case 'i':
                args.interval_seconds = std::stoi(optarg);
                if (args.interval_seconds < 1) args.interval_seconds = 1;
                break;
            case 'h':
                args.show_help = true;
                break;
            case 'l':
                args.show_listening_only = true;
                break;
            case 's':
                args.show_statistics = true;
                break;
            case 'c':
                args.show_compact = true;
                break;
            case '4':
                args.show_ipv6 = false;
                break;
            case 'p':
                args.filter_port = std::stoi(optarg);
                break;
            case 'P':
                args.filter_process = optarg;
                break;
            default:
                args.show_help = true;
                break;
        }
    }
    
    return args;
}

void printHelp(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n"
              << "TCP Port Scanner - просмотр открытых портов в Linux\n\n"
              << "Options:\n"
              << "  -w, --watch              Режим мониторинга (обновление каждые N секунд)\n"
              << "  -i, --interval N         Интервал обновления в секундах (по умолчанию: 2)\n"
              << "  -l, --listening          Показывать только слушающие порты\n"
              << "  -s, --stats              Показывать статистику по состояниям соединений\n"
              << "  -c, --compact            Компактный вывод (только порт, процесс, состояние)\n"
              << "  -4, --ipv4-only          Показывать только IPv4 соединения\n"
              << "  -p, --port PORT          Фильтр по номеру порта\n"
              << "  -P, --process NAME       Фильтр по имени процесса\n"
              << "  -h, --help               Показать эту справку\n\n"
              << "Examples:\n"
              << "  " << program_name << "                    # Разовый вывод всех соединений\n"
              << "  " << program_name << " --watch            # Мониторинг с обновлением каждые 2 сек\n"
              << "  " << program_name << " --watch --interval 3  # Мониторинг с интервалом 3 сек\n"
              << "  " << program_name << " --listening        # Только слушающие порты\n"
              << "  " << program_name << " --port 80          # Поиск процесса на порту 80\n"
              << "  " << program_name << " --process nginx    # Все соединения процесса nginx\n";
}


std::string getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    auto time_t1 = std::chrono::system_clock::to_time_t(now);
    
    std::tm tm; // localtime is not threadsafe, i guess localtime_r will do the trick
    ::localtime_r(&time_t1, &tm); // idk what i'm doing, i just rode the cpp docs
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}


std::vector<ConnectionInfo> applyFilters(const std::vector<ConnectionInfo>& connections, 
                                        const ProgramArgs& args) {
    std::vector<ConnectionInfo> result = connections;
    
    // filter by IPv4/IPv6
    if (!args.show_ipv6) {
        std::vector<ConnectionInfo> filtered;
        for (const auto& conn : result) {
            if (!conn.is_ipv6) {
                filtered.push_back(conn);
            }
        }
        result = filtered;
    }
    
    // filter by ports
    if (args.filter_port > 0) {
        std::vector<ConnectionInfo> filtered;
        for (const auto& conn : result) {
            if (conn.port == args.filter_port) {
                filtered.push_back(conn);
            }
        }
        result = filtered;
    }
    
    // filter by process
    if (!args.filter_process.empty()) {
        std::vector<ConnectionInfo> filtered;
        for (const auto& conn : result) {
            if (conn.process_name.find(args.filter_process) != std::string::npos) {
                filtered.push_back(conn);
            }
        }
        result = filtered;
    }
    
    // sort by ports
    std::sort(result.begin(), result.end(), 
              [](const ConnectionInfo& a, const ConnectionInfo& b) {
                  return a.port < b.port;
              });
    
    return result;
}

// Функция для вывода в обычном режиме
void printNormalMode(PortController& controller, const ProgramArgs& args, PortView& view) {
    controller.refresh(args.show_ipv6);
    auto all = controller.getAll();
    auto filtered = applyFilters(all, args);
    
    if (args.show_listening_only) {
        auto listening = controller.getListening();
        auto filtered_listening = applyFilters(listening, args);
        view.printListening(filtered_listening);
    } else if (args.show_compact) {
        view.printCompact(filtered);
    } else {
        view.printAll(filtered);
    }
    
    if (args.show_statistics) {
        auto stats = controller.getStateStatistics();
        view.printStatistics(stats);
    }
}

void printWatchMode(PortController& controller, const ProgramArgs& args, PortView& view) {
    // CLEAN THE SCREEN
    std::cout << "\033[2J\033[H";
    
    controller.refresh(args.show_ipv6);
    auto all = controller.getAll();
    auto filtered = applyFilters(all, args);
    
    // Header with time
    std::cout << "\033[1;32m=== TCP Port Scanner [Watch Mode] ===\033[0m\n";
    std::cout << "Last update: " << getCurrentTime() << "\n";
    std::cout << "Interval: " << args.interval_seconds << "s | Press Ctrl+C to exit\n";
    std::cout << std::string(80, '=') << "\n\n";
    
    if (args.show_listening_only) {
        auto listening = controller.getListening();
        auto filtered_listening = applyFilters(listening, args);
        view.printListening(filtered_listening);
    } else if (args.show_compact) {
        view.printCompact(filtered);
    } else {
        view.printAll(filtered);
    }
    
    if (args.show_statistics) {
        auto stats = controller.getStateStatistics();
        view.printStatistics(stats);
    }
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signalHandler);
    
    ProgramArgs args = parseArguments(argc, argv);
    
    if (args.show_help) {
        printHelp(argv[0]);
        return 0;
    }
    
    // init
    PortController controller;
    PortView view;
    
    // Watch Mode
    if (args.watch_mode) {
        std::cout << "Starting watch mode (interval: " << args.interval_seconds << "s)\n";
        std::cout << "Press Ctrl+C to stop\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        while (running) {
            printWatchMode(controller, args, view);
            
            // wait for interval until get rudely sent off by CTRL+C
            for (int i = 0; i < args.interval_seconds && running; ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
        
        std::cout << "\n\033[1;33mExiting watch mode...\033[0m\n";
    } else {
        // ONE ONE ONE ONE ONE ONE ONE ONE
        printNormalMode(controller, args, view);
    }
    
    return 0;
}