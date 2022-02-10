
add_executable(aby_test aby_test.cpp common/aby_test.cpp)
target_link_libraries(aby_test ABY::aby ENCRYPTO_utils::encrypto_utils)
