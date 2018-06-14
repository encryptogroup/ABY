
add_executable(threshold-euclidean-dist_test threshold-euclidean-dist.cpp common/threshold-euclidean-dist.cpp)
target_link_libraries(threshold-euclidean-dist_test ABY::aby ENCRYPTO_utils::encrypto_utils)
