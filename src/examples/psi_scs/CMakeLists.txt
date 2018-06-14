
add_executable(psi_scs_test psi_scs.cpp common/sort_compare_shuffle.cpp common/WaksmanPermutation.cpp)
target_link_libraries(psi_scs_test ABY::aby ENCRYPTO_utils::encrypto_utils)
