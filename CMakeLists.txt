## [main]

# Almost all CMake files should start with this
# You should always specify a range with the newest
# and oldest tested versions of CMake. This will ensure
# you pick up the best policies.
cmake_minimum_required(VERSION 3.10)

# This is your project statement. You should always list languages;
# Listing the version is nice here since it sets lots of useful variables
project(qsslkey-p11 VERSION 1.0 LANGUAGES CXX)

# If you set any CMAKE_ variables, that can go here.
# (But usually don't do this, except maybe for C++ standard)

# Find packages go here.

SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules ${CMAKE_MODULE_PATH})

set(CMAKE_AUTOMOC ON)

find_package(Qt5 COMPONENTS Core Widgets Network REQUIRED)
message(STATUS "Found Qt version: ${Qt5Core_VERSION_STRING}")

find_package(OpenSSL REQUIRED)
message(STATUS "Found OpenSSL version: ${OPENSSL_VERSION}")

find_package(LibP11 REQUIRED)
message(STATUS "Found libp11: ${LIBP11_LIBRARY}")

# You should usually split this into folders, but this is a simple example

# This is a "default" library, and will match the *** variable setting.
# Other common choices are STATIC, SHARED, and MODULE
# Including header files here helps IDEs but is not required.
# Output libname matches target name, with the usual extensions on your system
#add_library(MyLibExample simple_lib.cpp simple_lib.hpp)

# Link each target with other targets or add options, etc.

# Adding something we can run - Output name matches target name
add_executable(qsslkey-p11-engine
  qsslkey-p11-engine.cpp
)

add_executable(qsslkey-p11
  qsslkey-p11.cpp
  qgspkcs11.cpp
)

include_directories(
  ${Qt5Core_INCLUDE_DIRS}
  ${Qt5Widgets_INCLUDE_DIRS}
  ${Qt5Network_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIR}
  ${LIBP11_INCLUDE_DIR}
)

target_link_libraries(qsslkey-p11
  Qt5::Core
  Qt5::Widgets
  Qt5::Network
  ${OPENSSL_CRYPTO_LIBRARY}
  ${OPENSSL_SSL_LIBRARY}
  ${LIBP11_LIBRARY}
)

target_link_libraries(qsslkey-p11-engine
  Qt5::Core
  Qt5::Widgets
  Qt5::Network
  ${OPENSSL_CRYPTO_LIBRARY}
  ${OPENSSL_SSL_LIBRARY}
)

# Make sure you link your targets with this command. It can also link libraries and
# even flags, so linking a target that does not exist will not give a configure-time error.
#target_link_libraries(MyExample PRIVATE MyLibExample)

## [main]

# This part is so the Modern CMake book can verify this example builds. For your code,
# you'll probably want tests too
#enable_testing()
#add_test(NAME MyExample COMMAND MyExample)
