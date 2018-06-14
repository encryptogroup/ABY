
add_executable(bench_operations bench_operations.cpp ../aes/common/aescircuit.cpp)
target_link_libraries(bench_operations ABY::aby ENCRYPTO_utils::encrypto_utils)
