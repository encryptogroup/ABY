
add_executable(innerproduct_test innerproduct_test.cpp common/innerproduct.cpp)
target_link_libraries(innerproduct_test ABY::aby ENCRYPTO_utils::encrypto_utils)
if(ABY_ENABLE_MATRIX)
    target_compile_definitions(innerproduct_test PRIVATE ABY_ENABLE_MATRIX)
endif()
