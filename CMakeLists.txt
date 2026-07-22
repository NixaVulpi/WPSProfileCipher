cmake_minimum_required(VERSION 3.25)

if(POLICY CMP0091)
  cmake_policy(SET CMP0091 NEW)
endif()

project(
  wps_profile_cipher
  VERSION 2.0.0
  DESCRIPTION "Cross-platform WPS profile encryption, decryption, and OEM signing tool"
  LANGUAGES CXX
)

include(CTest)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

option(WPS_PROFILE_CIPHER_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(WPS_PROFILE_CIPHER_STATIC_MSVC_RUNTIME "Use the static MSVC runtime (/MT or /MTd)" ON)

if(MSVC)
  if(WPS_PROFILE_CIPHER_STATIC_MSVC_RUNTIME)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  else()
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  endif()
endif()

find_package(cryptopp CONFIG REQUIRED COMPONENTS static)
find_package(CLI11 CONFIG REQUIRED)
find_package(SimpleIni CONFIG REQUIRED)

add_library(
  wps_profile_cipher
  src/crypto/feature_codec.cpp
  src/crypto/oem_signature.cpp
  src/crypto/profile_value_cipher.cpp
  src/profile/profile_converter.cpp
  src/profile/profile_document.cpp
)
add_library(wps_profile_cipher::core ALIAS wps_profile_cipher)

target_compile_features(wps_profile_cipher PUBLIC cxx_std_20)
set_target_properties(
  wps_profile_cipher
  PROPERTIES
    CXX_EXTENSIONS OFF
    EXPORT_NAME core
    POSITION_INDEPENDENT_CODE ON
)
target_include_directories(
  wps_profile_cipher
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_definitions(wps_profile_cipher PRIVATE CRYPTOPP_ENABLE_NAMESPACE_WEAK=1)
target_link_libraries(wps_profile_cipher PRIVATE cryptopp::cryptopp SimpleIni::SimpleIni)

function(wps_enable_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8)
    if(WPS_PROFILE_CIPHER_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    if(WPS_PROFILE_CIPHER_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

wps_enable_warnings(wps_profile_cipher)

add_library(wps_profile_cipher_cli_support STATIC src/cli/command_line.cpp)
set_target_properties(wps_profile_cipher_cli_support PROPERTIES CXX_EXTENSIONS OFF)
target_compile_features(wps_profile_cipher_cli_support PUBLIC cxx_std_20)
target_compile_definitions(
  wps_profile_cipher_cli_support
  PRIVATE WPS_PROFILE_CIPHER_VERSION="${PROJECT_VERSION}"
)
target_link_libraries(
  wps_profile_cipher_cli_support
  PUBLIC wps_profile_cipher::core
  PRIVATE CLI11::CLI11
)
wps_enable_warnings(wps_profile_cipher_cli_support)

add_executable(wps_profile_cipher_cli src/cli/main.cpp)
set_target_properties(
  wps_profile_cipher_cli
  PROPERTIES
    CXX_EXTENSIONS OFF
    OUTPUT_NAME wps-profile-cipher
)
target_compile_features(wps_profile_cipher_cli PRIVATE cxx_std_20)
target_link_libraries(wps_profile_cipher_cli PRIVATE wps_profile_cipher_cli_support)
wps_enable_warnings(wps_profile_cipher_cli)

if(BUILD_TESTING)
  find_package(Catch2 3 CONFIG REQUIRED)
  add_executable(
    wps_profile_cipher_tests
    tests/command_line_tests.cpp
    tests/feature_codec_tests.cpp
    tests/oem_signature_tests.cpp
    tests/profile_converter_tests.cpp
    tests/profile_value_cipher_tests.cpp
  )
  set_target_properties(wps_profile_cipher_tests PROPERTIES CXX_EXTENSIONS OFF)
  target_compile_features(wps_profile_cipher_tests PRIVATE cxx_std_20)
  target_link_libraries(
    wps_profile_cipher_tests
    PRIVATE
      wps_profile_cipher::core
      wps_profile_cipher_cli_support
      cryptopp::cryptopp
      Catch2::Catch2WithMain
  )
  wps_enable_warnings(wps_profile_cipher_tests)
  include(Catch)
  catch_discover_tests(wps_profile_cipher_tests DISCOVERY_MODE PRE_TEST)
endif()

install(
  TARGETS wps_profile_cipher
  EXPORT wps_profile_cipher_targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(TARGETS wps_profile_cipher_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(
  EXPORT wps_profile_cipher_targets
  FILE wps_profile_cipher_targets.cmake
  NAMESPACE wps_profile_cipher::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wps_profile_cipher
)
configure_package_config_file(
  cmake/wps_profile_cipher-config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/wps_profile_cipher-config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wps_profile_cipher
)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/wps_profile_cipher-config-version.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)
install(
  FILES
    ${CMAKE_CURRENT_BINARY_DIR}/wps_profile_cipher-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/wps_profile_cipher-config-version.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wps_profile_cipher
)
install(FILES README.md LICENSE.md DESTINATION ${CMAKE_INSTALL_DOCDIR})

if(WIN32)
  set(CPACK_GENERATOR ZIP)
else()
  set(CPACK_GENERATOR TGZ)
endif()
if(NOT CPACK_PACKAGE_FILE_NAME)
  if(VCPKG_TARGET_TRIPLET MATCHES "^([^-]+)-")
    set(WPS_PROFILE_CIPHER_PACKAGE_ARCHITECTURE "${CMAKE_MATCH_1}")
  elseif(CMAKE_SYSTEM_PROCESSOR)
    set(WPS_PROFILE_CIPHER_PACKAGE_ARCHITECTURE "${CMAKE_SYSTEM_PROCESSOR}")
  else()
    set(WPS_PROFILE_CIPHER_PACKAGE_ARCHITECTURE "unknown")
  endif()
  if(WIN32)
    if(WPS_PROFILE_CIPHER_STATIC_MSVC_RUNTIME)
      set(WPS_PROFILE_CIPHER_PACKAGE_RUNTIME "mt")
    else()
      set(WPS_PROFILE_CIPHER_PACKAGE_RUNTIME "md")
    endif()
    set(WPS_PROFILE_CIPHER_PACKAGE_RUNTIME_SUFFIX "-${WPS_PROFILE_CIPHER_PACKAGE_RUNTIME}")
  else()
    set(WPS_PROFILE_CIPHER_PACKAGE_RUNTIME_SUFFIX "")
  endif()
  set(CPACK_PACKAGE_FILE_NAME "wps-profile-cipher-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}-${WPS_PROFILE_CIPHER_PACKAGE_ARCHITECTURE}${WPS_PROFILE_CIPHER_PACKAGE_RUNTIME_SUFFIX}")
endif()
set(CPACK_PACKAGE_VENDOR "WPS Profile Cipher contributors")
set(CPACK_PACKAGE_CHECKSUM SHA256)
include(CPack)
