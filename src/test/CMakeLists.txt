
add_executable(abytest
    abytest.cpp
    ../examples/aes/common/aescircuit.cpp
    ../examples/sha1/common/sha1_circuit.cpp
    ../examples/psi_scs/common/sort_compare_shuffle.cpp
    ../examples/psi_scs/common/WaksmanPermutation.cpp
    ../examples/psi_phasing/common/phasing_circuit.cpp
    ../examples/psi_phasing/common/hashing/simple_hashing.cpp
    ../examples/psi_phasing/common/hashing/cuckoo.cpp
)
target_compile_options(abytest PRIVATE "-Wall" "-Wextra")
target_link_libraries(abytest ABY::aby ENCRYPTO_utils::encrypto_utils)
