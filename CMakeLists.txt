cmake_minimum_required(VERSION 3.14)
project(NetSentinel LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Opt-in build options. ALL default to OFF: the default build, flags and behaviour are unchanged. ---
option(NS_STRICT_WARNINGS "Compile project sources (not Catch2/tests) with -Wall -Wextra -Wpedantic -Wshadow -Wconversion" OFF)
option(NS_SANITIZE "Build project targets with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
add_library(ns_warnings INTERFACE)
add_library(ns_sanitizers INTERFACE)
if(NS_STRICT_WARNINGS AND NOT MSVC)
  target_compile_options(ns_warnings INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
endif()
if(NS_SANITIZE AND NOT MSVC)
  target_compile_options(ns_sanitizers INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer -g)
  target_link_options(ns_sanitizers INTERFACE -fsanitize=address,undefined)
endif()

# --- Catch2 test framework, fetched with FetchContent (v3.5.2).
include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2
)
FetchContent_MakeAvailable(Catch2)

# --- libpcap, required for PCAP-file ingestion
# pkg-config first (unchanged behaviour where it works); otherwise fall back to a plain header/library search.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(PCAP QUIET libpcap)
endif()
if(NOT PCAP_FOUND)
  find_path(PCAP_INCLUDE_DIRS pcap/pcap.h)
  find_library(PCAP_LIBRARIES pcap)
  if(NOT PCAP_INCLUDE_DIRS OR NOT PCAP_LIBRARIES)
    message(FATAL_ERROR "libpcap not found (pkg-config and fallback search both failed). Install libpcap development files.")
  endif()
  message(STATUS "libpcap located without pkg-config: ${PCAP_LIBRARIES} (headers: ${PCAP_INCLUDE_DIRS})")
else()
  message(STATUS "libpcap located via pkg-config: version ${PCAP_VERSION}")
endif()

# --- Core implementation library, shared between the main executable
# and the test suite: the statistics engine (src/StatEngine.cpp) and the
# pipeline components below.
add_library(netsentinel_stats src/StatEngine.cpp)
target_include_directories(netsentinel_stats PUBLIC include)
target_link_libraries(netsentinel_stats PUBLIC ns_sanitizers PRIVATE ns_warnings)

add_library(netsentinel_core
    src/PcapFileCapture.cpp
    src/FeatureExtractor.cpp
    src/WindowAggregator.cpp
    src/AnomalyScorer.cpp
    src/ConsoleAlertEmitter.cpp
    src/Pipeline.cpp
    src/TraceWriter.cpp
)
target_include_directories(netsentinel_core PUBLIC include ${PCAP_INCLUDE_DIRS})
target_link_libraries(netsentinel_core PUBLIC netsentinel_stats ${PCAP_LIBRARIES} PRIVATE ns_warnings)

# --- Main executable: the full pipeline
add_executable(netsentinel src/main.cpp)
target_link_libraries(netsentinel PRIVATE netsentinel_core ns_warnings)

# --- Statistics engine tests
add_executable(netsentinel_tests tests/test_stat_engine.cpp)
target_link_libraries(netsentinel_tests PRIVATE netsentinel_stats Catch2::Catch2WithMain)

enable_testing()
add_test(NAME StatEngineTests COMMAND netsentinel_tests)

# --- Unit tests for the pipeline components (capture, extractor, window/time policy, baseline policy).
add_executable(netsentinel_unit tests/unit/test_capture.cpp tests/unit/test_feature_extractor.cpp tests/unit/test_pipeline.cpp tests/unit/test_policy.cpp tests/unit/test_stat_boundary.cpp)
target_compile_definitions(netsentinel_unit PRIVATE NS_SOURCE_DIR="${CMAKE_SOURCE_DIR}")
target_link_libraries(netsentinel_unit PRIVATE netsentinel_core Catch2::Catch2WithMain)
add_test(NAME UnitTests COMMAND netsentinel_unit)

# --- Fixture verification. Tests only: no target, flag or dependency above is changed. ---
add_test(NAME fixtures_verify
         COMMAND ${CMAKE_COMMAND} -DROOT=${CMAKE_SOURCE_DIR} -P ${CMAKE_SOURCE_DIR}/tests/fixtures/verify_fixtures.cmake)
find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
  add_test(NAME fixtures_regenerate
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/fixtures/check_regeneration.py ${CMAKE_SOURCE_DIR})
else()
  message(WARNING "Python3 not found: Python-based tests are replaced by a test that FAILS loudly.")
  add_test(NAME python3_required COMMAND ${CMAKE_COMMAND} -P ${CMAKE_SOURCE_DIR}/tests/fixtures/python_missing.cmake)
endif()

# --- Characterization (golden) and oracle cross-check tests. Tests only; no target above is changed. ---
if(Python3_FOUND)
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/tests/golden/MANIFEST.tsv)
  file(STRINGS ${CMAKE_SOURCE_DIR}/tests/golden/MANIFEST.tsv _golden_rows)
  foreach(_row IN LISTS _golden_rows)
    if(NOT _row MATCHES "^#")
      string(REGEX MATCH "^[^\t]+" _name "${_row}")
      add_test(NAME golden_${_name}
               COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/golden/run_golden.py
                       --exe $<TARGET_FILE:netsentinel> --root ${CMAKE_SOURCE_DIR} --name ${_name})
    endif()
  endforeach()
  foreach(_n sample_original sample_regenerated gap boundary)
    add_test(NAME oracle_${_n}
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/oracle/oracle_crosscheck.py
                     --exe $<TARGET_FILE:netsentinel> --root ${CMAKE_SOURCE_DIR} --name ${_n})
  endforeach()

  # --- Audit regression fixtures (tests/data/audit, generated by tests/fixtures/make_audit_fixtures.py).
  # audit_<name>: closure check for the defect the fixture isolates; oracle_audit_<name>: full cross-check
  # against the independent Python reading of the time/window contract.
  set(_audit_fixtures future_ts_glitch epoch_zero_first truncated_file truncated_file_full no_attack_with_tail
      gap_10min ipv6_attack vlan_tagged linux_sll unsupported_linktype snaplen64 fragments tcp_truncated_hdr
      constant_then_scan constant_then_scan_tail)
  add_test(NAME cli_and_trace
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/regression/check_cli_trace.py
                   --exe $<TARGET_FILE:netsentinel> --root ${CMAKE_SOURCE_DIR})
  foreach(_n IN LISTS _audit_fixtures)
    add_test(NAME audit_${_n}
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/regression/check_audit.py
                     --exe $<TARGET_FILE:netsentinel> --root ${CMAKE_SOURCE_DIR} --name ${_n})
    if(NOT _n STREQUAL "unsupported_linktype")
      add_test(NAME oracle_audit_${_n}
               COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/oracle/oracle_crosscheck.py
                       --exe $<TARGET_FILE:netsentinel> --root ${CMAKE_SOURCE_DIR} --pcap tests/data/audit/${_n}.pcap)
    endif()
  endforeach()
  # --- Evaluation tooling self-tests (toy evaluator case, original-prototype console parser, CICFlowMeter-format stand-in).
  add_test(NAME eval_tools
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/eval/test_eval_tools.py
                   --exe $<TARGET_FILE:netsentinel> --root ${CMAKE_SOURCE_DIR})
  add_test(NAME audit_constant_then_scan_tail_gated_sd_floor
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/regression/check_audit.py
                   --exe $<TARGET_FILE:netsentinel> --root ${CMAKE_SOURCE_DIR} --name constant_then_scan_tail@gated_sd_floor)
endif()
