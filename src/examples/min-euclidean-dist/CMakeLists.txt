
add_executable(min-euclidean-dist_test min-euclidean-dist.cpp common/min-euclidean-dist-circuit.cpp)
target_link_libraries(min-euclidean-dist_test ABY::aby ENCRYPTO_utils::encrypto_utils)
