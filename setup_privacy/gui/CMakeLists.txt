cmake_minimum_required(VERSION 3.21)

project(SecurityDNS VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Gui Widgets Network)

set(SDNS_SOURCES
    src/main.cpp
    src/core/CommandRunner.cpp
    src/core/CommandRunner.h
    src/core/Engine.cpp
    src/core/Engine.h
    src/core/HttpClient.cpp
    src/core/HttpClient.h
    src/core/Platform.cpp
    src/core/Platform.h
    src/core/Settings.cpp
    src/core/Settings.h
    src/core/SystemConfig.cpp
    src/core/SystemConfig.h
    src/core/ToolManager.cpp
    src/core/ToolManager.h
    src/core/Translator.cpp
    src/core/Translator.h
    src/core/Types.h
    src/ui/ErrorDialog.cpp
    src/ui/ErrorDialog.h
    src/ui/MainWindow.cpp
    src/ui/MainWindow.h
    src/ui/SettingsPage.cpp
    src/ui/SettingsPage.h
    src/ui/Theme.cpp
    src/ui/Theme.h
    src/ui/ToolsPage.cpp
    src/ui/ToolsPage.h
    resources/resources.qrc
)

add_executable(security-dns WIN32 ${SDNS_SOURCES})

target_include_directories(security-dns PRIVATE src)
target_compile_definitions(security-dns PRIVATE APP_VERSION="${PROJECT_VERSION}")
target_link_libraries(security-dns PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network)

if(WIN32)
    target_link_libraries(security-dns PRIVATE wininet shell32 advapi32 user32)
    if(MSVC)
        # Ask for administrator rights at launch (UAC prompt).
        target_link_options(security-dns PRIVATE "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'")
    endif()
endif()

install(TARGETS security-dns RUNTIME DESTINATION bin)
if(UNIX AND NOT APPLE)
    install(FILES packaging/security-dns.desktop DESTINATION share/applications)
endif()
