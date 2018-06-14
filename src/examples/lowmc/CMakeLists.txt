
add_executable(lowmc_test lowmc.cpp common/lowmccircuit.cpp)
target_link_libraries(lowmc_test ABY::aby ENCRYPTO_utils::encrypto_utils)
