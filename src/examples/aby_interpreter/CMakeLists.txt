
add_executable(aby_interpreter aby_interpreter.cpp common/aby_interpreter.cpp)
target_link_libraries(aby_interpreter ABY::aby ENCRYPTO_utils::encrypto_utils)
