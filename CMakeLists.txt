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

    add_executable(test_fec_diag bench/test_fec_diag.c)
    anliu_configure_test(test_fec_diag)
    set_target_properties(test_fec_diag PROPERTIES C_EXTENSIONS OFF)
    if(UNIX)
        target_link_libraries(test_fec_diag PRIVATE m)
    endif()
    add_test(NAME anliu.fec_accounting COMMAND test_fec_diag)
endif()

if(UNIX AND (ANLIU_BUILD_BENCHMARKS OR
    (BUILD_TESTING AND CMAKE_SYSTEM_NAME STREQUAL "Linux")))
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
endif()

function(anliu_configure_tool target)
    anliu_configure_target(${target})
    set_target_properties(${target} PROPERTIES
        C_EXTENSIONS ON RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bench)
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${target} PRIVATE anliu_bench_kcp m)
endfunction()

if(ANLIU_BUILD_BENCHMARKS)
    if(UNIX)
        add_executable(anl_bench bench/bench.c)
        anliu_configure_tool(anl_bench)
        target_link_libraries(anl_bench PRIVATE anliu)

        add_executable(anl_media_startup bench/media_startup.c)
        anliu_configure_tool(anl_media_startup)
        target_link_libraries(anl_media_startup PRIVATE anliu)

        # capacity_step.c includes anliu.c itself for internal diagnostics.
        add_executable(anl_capacity_step bench/capacity_step.c)
        anliu_configure_tool(anl_capacity_step)

        # CPU per segment against window / BDP / loss (DESIGN 5.1).
        add_executable(anl_wndcost bench/wndcost.c)
        anliu_configure_tool(anl_wndcost)
        target_link_libraries(anl_wndcost PRIVATE anliu)

        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            add_executable(realnet bench/realnet.c)
            anliu_configure_tool(realnet)
            target_link_libraries(realnet PRIVATE anliu)

            add_executable(realnet_trace bench/realnet.c)
            anliu_configure_tool(realnet_trace)
            target_compile_definitions(realnet_trace PRIVATE REALNET_INTERNAL)
        else()
            message(STATUS "Linux TCP diagnostics are required by realnet; skipping realnet targets")
        endif()
    else()
        message(STATUS "POSIX clocks are required by simulation tools; skipping benchmark targets")
    endif()
endif()

if(BUILD_TESTING AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_tx_diag bench/test_tx_diag.c)
    anliu_configure_tool(test_tx_diag)
    anliu_configure_test(test_tx_diag)
    target_compile_definitions(test_tx_diag PRIVATE REALNET_INTERNAL)
    add_test(NAME anliu.tx_accounting COMMAND test_tx_diag)

    add_executable(test_media_workload bench/test_media_workload.c)
    anliu_configure_tool(test_media_workload)
    anliu_configure_test(test_media_workload)
    target_link_libraries(test_media_workload PRIVATE anliu)
    add_test(NAME anliu.media_workload COMMAND test_media_workload)

    # media_loss.c includes anliu.c and bench.c for internal tracing. The
    # end-to-end auto-FEC check is not part of ctest; run it on a sanitizer build:
    #   python3 bench/test_media_loss.py build/bench/anl_media_loss
    add_executable(anl_media_loss bench/media_loss.c)
    anliu_configure_tool(anl_media_loss)
endif()

if(BUILD_TESTING)
    set_tests_properties(anliu.unit anliu.fec_accounting PROPERTIES TIMEOUT 180)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set_tests_properties(anliu.tx_accounting anliu.media_workload PROPERTIES TIMEOUT 30)
    endif()
endif()

install(TARGETS anliu EXPORT AnLiuTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES anliu.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/AnLiu)
install(EXPORT AnLiuTargets FILE AnLiuConfig.cmake NAMESPACE AnLiu::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/AnLiu)
