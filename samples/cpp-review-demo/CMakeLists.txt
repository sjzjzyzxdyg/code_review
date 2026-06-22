cmake_minimum_required(VERSION 3.16)
project(cpp_review_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(cpp_review_demo src/main.cpp)
target_include_directories(cpp_review_demo PRIVATE include)

