
add_executable(uc_circuit_test uc_circuit_test.cpp common/uc_circuit.cpp)
target_link_libraries(uc_circuit_test ABY::aby ENCRYPTO_utils::encrypto_utils)
