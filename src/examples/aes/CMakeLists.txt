
add_executable(aes_test aes_test.cpp common/aescircuit.cpp)
target_link_libraries(aes_test ABY::aby ENCRYPTO_utils::encrypto_utils)
