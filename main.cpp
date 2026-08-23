#include "controller.hpp"
#include "view.hpp"
#include <iostream>
#include <unistd.h>

int main(int argc, char* argv[]) {
    std::cout << "=== TCP Port Scanner (MVC Architecture) ===\n";
    std::cout << "PID: " << getpid() << "\n\n";
    
    // __init CV
    PortController controller;
    PortView view;
    
    controller.refresh(true); // true = including IPv6
    
    auto all = controller.getAll();
    view.printAll(all);
    
    return 0;
}