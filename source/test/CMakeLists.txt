
add_executable(test_aes aes.cpp)
target_link_libraries(test_aes PRIVATE doctest understanding_crypto)
target_compile_definitions(test_aes PRIVATE DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN)
add_test(NAME test_aes COMMAND test_aes)