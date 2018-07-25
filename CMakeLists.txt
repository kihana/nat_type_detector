cmake_minimum_required(VERSION 3.12)

project(nat_type_detector)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

set(SOURCES src/NatTypeDetector.cpp src/StunMessage.cpp src/main.cpp src/StunController.cpp src/StunAttribute.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})
