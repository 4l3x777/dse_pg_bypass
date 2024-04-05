cmake_minimum_required(VERSION 3.22)

set(PATCH_VERSION "1" CACHE INTERNAL "Patch version")
set(PROJECT_VESRION 0.0.${PATCH_VERSION})
project(DSE_PG_BYPASS VERSION ${PROJECT_VESRION})

include_directories(includes src)

add_executable(
  dse_pg_bypass
  src/amd.cpp
  src/byovd.cpp
  src/kernel_utils.cpp
  src/pattern.cpp
  src/dse_pg_bypass.cpp
)

set_target_properties(
  dse_pg_bypass
  PROPERTIES
  CXX_STANDARD 17
  CXX_STANDARD_REQUIRED ON
)

if (MSVC)
  target_compile_options(dse_pg_bypass PRIVATE /W4)
else ()
  target_link_options(dse_pg_bypass PRIVATE -static-libgcc -static-libstdc++)

  target_compile_options(
    dse_pg_bypass 
    PRIVATE
    -Wall 
    -Wextra 
    -pedantic 
  )
endif()

install(
    TARGETS 
    dse_pg_bypass
    RUNTIME DESTINATION . COMPONENT release
)

set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL release)

# CPack area
if (WIN32)
  set(CPACK_GENERATOR "ZIP")
else()
  set(CPACK_GENERATOR "DEB")
endif()
set(CPACK_PACKAGE_VERSION "0.0.1")
set(CPACK_PACKAGE_VERSION_MAJOR "0")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "1")
set(CPACK_PACKAGE_CONTACT https://github.com/4l3x777/dse_pg_bypass)
include(CPack)