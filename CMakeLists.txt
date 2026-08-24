cmake_minimum_required(VERSION 3.10)
project(portscan VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(portscan
    src/main.cpp
    src/scanner.cpp
    src/controller.cpp
    src/view.cpp
)

target_include_directories(portscan PRIVATE src)
