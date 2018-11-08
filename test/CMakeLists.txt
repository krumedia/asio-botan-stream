CMAKE_MINIMUM_REQUIRED( VERSION 3.0.2 )


PROJECT(asio-botan-stream-test)

enable_testing()

find_package(GTest REQUIRED)
find_package(Boost 1.58.0 COMPONENTS filesystem REQUIRED)

find_path(BOTAN_INCLUDE_DIR NAMES botan.h PATH botan/)
find_library(BOTAN_LIBRARY NAMES botan)
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Botan
	DEFAULT_MSG
	BOTAN_LIBRARY
	BOTAN_INCLUDE_DIR)

include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR} ${BOTAN_INCLUDE_DIR})

add_executable (asio-botan-stream-test main.cpp)

target_link_libraries (asio-botan-stream-test asio-botan-stream
  GTest::GTest GTest::Main
  ${BOTAN_LIBRARY}
  ${Boost_LIBRARIES}
)

