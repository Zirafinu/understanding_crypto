add_library(understanding_crypto INTERFACE)
target_include_directories(understanding_crypto
    INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

add_subdirectory(test)