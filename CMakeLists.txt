cmake_minimum_required(VERSION 3.20)

project(PasswordManager VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

option(PASSWORD_MANAGER_BUILD_GUI "Build the Password Manager desktop application" ON)
option(PASSWORD_MANAGER_FETCH_RAYLIB "Download raylib automatically when it is not installed" ON)

if(PASSWORD_MANAGER_BUILD_GUI)
    find_package(raylib 5.0 QUIET)
    if(NOT raylib_FOUND)
        if(PASSWORD_MANAGER_FETCH_RAYLIB)
            include(FetchContent)
            set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
            set(BUILD_GAMES OFF CACHE BOOL "" FORCE)
            FetchContent_Declare(
                raylib
                GIT_REPOSITORY https://github.com/raysan5/raylib.git
                GIT_TAG 5.5
                GIT_SHALLOW TRUE
            )
            FetchContent_MakeAvailable(raylib)
        else()
            message(FATAL_ERROR "raylib 5.x was not found. Install raylib or configure with -DPASSWORD_MANAGER_FETCH_RAYLIB=ON.")
        endif()
    endif()

    add_executable(password_manager main.c crypto.c storage.c entry.c)

    target_include_directories(password_manager PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(password_manager PRIVATE raylib OpenSSL::Crypto)
    set_target_properties(password_manager PROPERTIES OUTPUT_NAME "PasswordManager")

    if(MSVC)
        target_compile_options(password_manager PRIVATE /W4)
    else()
        target_compile_options(password_manager PRIVATE -Wall -Wextra -Wpedantic -Wno-unused-parameter)
    endif()
endif()

include(CTest)
if(BUILD_TESTING)
    add_executable(password_manager_tests
        tests/crypto_storage_test.c
        crypto.c
        storage.c
    )
    target_include_directories(password_manager_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(password_manager_tests PRIVATE OpenSSL::Crypto)
    if(MSVC)
        target_compile_options(password_manager_tests PRIVATE /W4)
    else()
        target_compile_options(password_manager_tests PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME crypto_storage COMMAND password_manager_tests)
endif()
