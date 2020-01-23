add_executable(euclidean_simd euclidean_simd.cpp common/euclidean_simd.cpp)
target_link_libraries(euclidean_simd ABY::aby ENCRYPTO_utils::encrypto_utils)
