SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TEST_CFLAGS} -fPIE")

add_executable(aul_test
		aul_test.c)
target_link_libraries(aul_test aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS aul_test DESTINATION bin)

add_executable(launch_app
		launch_app.c)
target_link_libraries(launch_app aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS launch_app DESTINATION bin)

# test
add_executable(open_app
                open_app.c)
target_link_libraries(open_app aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS open_app DESTINATION bin)

add_executable(appid2pid
                appid2pid.c)
target_link_libraries(appid2pid aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS appid2pid DESTINATION bin)

add_executable(launch_debug
                launch_debug.c)
target_link_libraries(launch_debug aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS launch_debug DESTINATION bin)

add_executable(app_launcher
		app_launcher.c)
target_link_libraries(app_launcher aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS app_launcher DESTINATION bin)

add_executable(appgroup_info
		app_group_info.c)
target_link_libraries(appgroup_info aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS appgroup_info DESTINATION bin)

add_executable(app_com_tool
		app_com_tool.c)
target_link_libraries(app_com_tool aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS app_com_tool DESTINATION bin)
