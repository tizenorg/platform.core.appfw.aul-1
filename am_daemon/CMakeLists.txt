SET(AMD "amd")

ADD_EXECUTABLE(${AMD}
	amd_main.c
	amd_request.c
	amd_appinfo.c
	amd_launch.c
	amd_status.c)

pkg_check_modules(AMD_DEPS REQUIRED
	dlog
	app-checker
	app-checker-server
	ail
	glib-2.0
	vconf
	pkgmgr-info
	libprivilege-control
	privacy-manager-client)
FOREACH(FLAGS ${AMD_DEPS_CFLAGS})
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FLAGS}")
ENDFOREACH(FLAGS)

# Linker flags
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

TARGET_LINK_LIBRARIES(${AMD} ${AUL_MODS} ${AUL} ${AMD_DEPS_LDFLAGS})

INSTALL(TARGETS ${AMD} DESTINATION bin)
