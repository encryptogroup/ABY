
add_executable(sha1_test sha1_test.cpp common/sha1_circuit.cpp)
target_link_libraries(sha1_test ABY::aby ENCRYPTO_utils::encrypto_utils)
