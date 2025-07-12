cmake_minimum_required(VERSION 3.22)

# Allow PATCH_VERSION override from command line/environment
option(PATCH_VERSION "Patch version" "2")

set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH ${PATCH_VERSION})
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

project(DSE_PG_BYPASS VERSION ${PROJECT_VERSION})

add_executable(
  dse_pg_bypass
  src/amd.cpp
  src/byovd.cpp
  src/kernel_utils.cpp
  src/pattern.cpp
  src/dse_pg_bypass.cpp
)

target_include_directories(dse_pg_bypass PRIVATE includes src)

set_target_properties(
  dse_pg_bypass
  PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

if (MSVC)
  target_compile_options(dse_pg_bypass PRIVATE /W4)
else()
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
  TARGETS dse_pg_bypass
  RUNTIME DESTINATION . COMPONENT release
)

# --- CPack configuration for packaging ---
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL release)

if (WIN32)
  set(CPACK_GENERATOR "ZIP")
else()
  set(CPACK_GENERATOR "DEB")
endif()

set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})
set(CPACK_PACKAGE_CONTACT "https://github.com/4l3x777/dse_pg_bypass")

include(CPack)