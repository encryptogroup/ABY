add_executable(two_aby_test two_aby_test.cpp common/two_aby.cpp)
target_link_libraries(two_aby_test ABY::aby ENCRYPTO_utils::encrypto_utils)
