# Test executables

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TEST_CFLAGS} -fPIE")

add_executable(aul_test
		aul_test.c)
target_link_libraries(aul_test aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS aul_test DESTINATION bin)

add_executable(launch_app
		launch_app.c)
target_link_libraries(launch_app aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS launch_app DESTINATION bin)

add_executable(open_app
                open_app.c)
target_link_libraries(open_app aul ${pkgs_LDFLAGS} "-pie")
INSTALL(TARGETS open_app DESTINATION bin)
