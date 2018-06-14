
add_executable(millionaire_prob_test millionaire_prob_test.cpp common/millionaire_prob.cpp)
target_link_libraries(millionaire_prob_test ABY::aby ENCRYPTO_utils::encrypto_utils)
