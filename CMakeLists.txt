cmake_minimum_required(VERSION 3.16)
project(AnLiu LANGUAGES C)

include(GNUInstallDirs)
include(CTest)

option(ANLIU_BUILD_BENCHMARKS "Build simulation and real-network tools" ON)
option(ANLIU_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

if(ANLIU_ENABLE_SANITIZERS AND NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR "ANLIU_ENABLE_SANITIZERS requires GCC or Clang")
endif()

function(anliu_configure_target target)
    target_compile_features(${target} PRIVATE c_std_99)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endif()
    if(ANLIU_ENABLE_SANITIZERS)
        target_compile_options(${target} PRIVATE
            -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${target} PUBLIC -fsanitize=address,undefined)
    endif()
endfunction()

function(anliu_configure_test target)
    anliu_configure_target(${target})
    # Diagnostics use assert for checks and setup, including in Release builds.
    if(MSVC)
        target_compile_options(${target} PRIVATE /UNDEBUG)
    else()
        target_compile_options(${target} PRIVATE -UNDEBUG)
    endif()
endfunction()

add_library(anliu STATIC anliu.c)
add_library(AnLiu::anliu ALIAS anliu)
anliu_configure_target(anliu)
target_compile_features(anliu PUBLIC c_std_99)
set_target_properties(anliu PROPERTIES C_EXTENSIONS OFF)
target_include_directories(anliu PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

if(BUILD_TESTING)
    # The existing tests include anliu.c to inspect internal state. Do not link
    # a second copy of the implementation through the library target.
    add_executable(anl_test test.c)
    anliu_configure_test(anl_test)
    set_target_properties(anl_test PROPERTIES C_EXTENSIONS OFF)
    if(UNIX)
        target_link_libraries(anl_test PRIVATE m)
    endif()
    add_test(NAME anliu.unit COMMAND anl_test)
    set_tests_properties(anliu.unit PROPERTIES TIMEOUT 180)
endif()

if(ANLIU_BUILD_BENCHMARKS)
    if(UNIX)
        # KCP is only a comparison-tool dependency; the AnLiu library is standalone.
        add_library(anliu_bench_kcp STATIC bench/ikcp.c)
        target_include_directories(anliu_bench_kcp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/bench)
        target_compile_features(anliu_bench_kcp PRIVATE c_std_99)
        set_target_properties(anliu_bench_kcp PROPERTIES C_EXTENSIONS ON)
        if(ANLIU_ENABLE_SANITIZERS)
            target_compile_options(anliu_bench_kcp PRIVATE
                -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer)
            target_link_options(anliu_bench_kcp PUBLIC -fsanitize=address,undefined)
        endif()

        add_executable(anl_bench bench/bench.c)
        anliu_configure_target(anl_bench)
        set_target_properties(anl_bench PROPERTIES
            C_EXTENSIONS ON RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bench)
        target_link_libraries(anl_bench PRIVATE anliu anliu_bench_kcp m)

        add_executable(realnet bench/realnet.c)
        anliu_configure_target(realnet)
        set_target_properties(realnet PROPERTIES
            C_EXTENSIONS ON RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bench)
        target_link_libraries(realnet PRIVATE anliu anliu_bench_kcp m)
    else()
        message(STATUS "POSIX clocks are required by simulation tools; skipping benchmark targets")
    endif()
endif()

install(TARGETS anliu EXPORT AnLiuTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES anliu.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/AnLiu)
install(EXPORT AnLiuTargets FILE AnLiuConfig.cmake NAMESPACE AnLiu::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AnLiu)
