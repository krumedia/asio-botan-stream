cmake_minimum_required(VERSION 3.0)

project(asio-botan-stream)


find_package(Boost 1.58.0 COMPONENTS system REQUIRED)

add_library(asio-botan-stream INTERFACE)
target_include_directories(asio-botan-stream INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>)
target_include_directories(asio-botan-stream INTERFACE ${Boost_INCLUDE_DIRS})
target_link_libraries(asio-botan-stream INTERFACE ${Boost_LIBRARIES})


option(BUILD_TESTING "Build tests" ON)
IF(BUILD_TESTING)
	add_subdirectory(test)
ENDIF()