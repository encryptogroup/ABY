add_executable(addition_test addition_test.cpp common/addition.cpp) 
target_link_libraries(addition_test ABY::aby ENCRYPTO_utils::encrypto_utils)
