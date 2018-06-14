
add_executable(psi_phasing_test psi_phasing.cpp common/phasing_circuit.cpp
	common/hashing/cuckoo.cpp common/hashing/simple_hashing.cpp)
target_link_libraries(psi_phasing_test ABY::aby ENCRYPTO_utils::encrypto_utils)
