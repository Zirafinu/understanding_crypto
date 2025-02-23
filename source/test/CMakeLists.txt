add_library(test_main OBJECT doctest_main.cpp)
target_link_libraries(test_main PUBLIC doctest)

add_executable(test_aes aes.cpp)
target_link_libraries(test_aes PRIVATE test_main understanding_crypto)
add_test(NAME test_aes COMMAND test_aes)

add_executable(test_biginteger biginteger.cpp)
target_link_libraries(test_biginteger PRIVATE test_main understanding_crypto)
add_test(NAME test_biginteger COMMAND test_biginteger)
