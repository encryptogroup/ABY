
add_executable(simd simd_test.cpp common/simd.cpp)
target_link_libraries(simd ABY::aby ENCRYPTO_utils::encrypto_utils)
