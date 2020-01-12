add_executable(two_euclidean_test two_euclidean_test.cpp common/two_euclidean.cpp)
target_link_libraries(two_euclidean_test ABY::aby ENCRYPTO_utils::encrypto_utils)
