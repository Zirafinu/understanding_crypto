cmake_minimum_required(VERSION 3.28)
project(understanding_crypto CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()
include(dependencies.cmake)
add_subdirectory(source)
