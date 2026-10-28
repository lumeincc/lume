# SPDX-FileCopyrightText: 2026 LUME Inc.
# SPDX-License-Identifier: AGPL-3.0-only

add_executable(lume_lab main.cpp report.cpp walkthrough.cpp ${PROJECT_SOURCE_DIR}/core/tests/support/curve.cpp)
set_target_properties(lume_lab PROPERTIES OUTPUT_NAME lume-lab)
target_include_directories(lume_lab PRIVATE ${PROJECT_SOURCE_DIR}/core/tests)
target_link_libraries(lume_lab PRIVATE lume::core)
lume_configure_target(lume_lab)

if(LUME_BUILD_TESTS)
    add_test(NAME lab.walkthrough COMMAND lume_lab)
endif()
