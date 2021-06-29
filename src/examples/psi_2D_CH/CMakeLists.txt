
add_executable(psi_2D_CH_test psi_2D_CH.cpp common/psi_2D_CH_circuit.cpp
	common/hashing/cuckoo.cpp common/hashing/simple_hashing.cpp)
target_link_libraries(psi_2D_CH_test ABY::aby ENCRYPTO_utils::encrypto_utils)
