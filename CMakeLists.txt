CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)

PROJECT(aul C)

ADD_DEFINITIONS("-DSHARE_PREFIX=\"${SHARE_INSTALL_PREFIX}/aul\"")
IF (with_wayland)
       ADD_DEFINITIONS("-DWAYLAND")
ENDIF (with_wayland)
IF (with_x11)
       ADD_DEFINITIONS("-DX11")
ENDIF (with_x11)

# Set required packages
INCLUDE(FindPkgConfig)
SET(AUL-1_LIB_PKG_CHECK_MODULES dlog bundle xdgmime libtzplatform-config pkgmgr-info capi-system-info vconf sqlite3 iniparser gio-2.0 glib-2.0 libxml-2.0 ttrace)
IF (with_wayland)
	pkg_check_modules(libpkgs REQUIRED ${AUL-1_LIB_PKG_CHECK_MODULES} wayland-client tizen-extension-client ecore-wayland)
ENDIF (with_wayland)
IF (with_x11)
	pkg_check_modules(libpkgs REQUIRED ${AUL-1_LIB_PKG_CHECK_MODULES})
ENDIF (with_x11)
IF(TIZEN_FEATURE_DEFAULT_USER)
	ADD_DEFINITIONS("-DTIZEN_FEATURE_DEFAULT_USER")
ENDIF(TIZEN_FEATURE_DEFAULT_USER)
FOREACH(flag ${libpkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

pkg_check_modules(APP_LAUNCHER_DEPS glib-2.0 pkgmgr-info bundle)
FOREACH(APP_LAUNCHER_FLAGS ${APP_LAUNCHER_DEPS_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${APP_LAUNCHER_FLAGS}")
ENDFOREACH(APP_LAUNCHER_FLAGS)

# Compiler flags
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/legacy)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/feature)
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Wl,-zdefs" )
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fvisibility=hidden")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -fpic")
SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} -Werror")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS}")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")
SET(CMAKE_C_FLAGS_RELEASE "-O2")
SET(CMAKE_SKIP_BUILD_RPATH true)
# Linker flags
SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed")

# aul
add_library(aul SHARED
		src/pkginfo.c
		src/launch.c
		src/launch_glib.c
		src/launch_with_result.c
		src/service.c
		src/service_db.c
		src/mime.c
		src/miregex.c
		src/app_signal.c
		src/key.c
		src/status.c
		src/aul_path.c
		src/app_group.c
		src/aul_rsc_mgr.c
		src/aul_rsc_mgr_internal.c
		src/aul_sock.c
		src/aul_proc.c
		src/app_com.c
		src/aul_error.c
		src/app_data.c
		)
TARGET_LINK_LIBRARIES(aul ${libpkgs_LDFLAGS})
SET_TARGET_PROPERTIES(aul PROPERTIES SOVERSION ${MAJORVER})
SET_TARGET_PROPERTIES(aul PROPERTIES VERSION ${FULLVER})
INSTALL(TARGETS aul DESTINATION ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)

# pkgconfig file
CONFIGURE_FILE(aul.pc.in aul.pc @ONLY)
CONFIGURE_FILE(feature/preexec_list.txt.in feature/preexec_list.txt @ONLY)

# Install headers, other files
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/aul.h DESTINATION include/aul)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/aul_sock.h DESTINATION include/aul)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/aul_proc.h DESTINATION include/aul)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/aul_rsc_mgr.h DESTINATION include/aul)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/aul_svc.h DESTINATION include/aul)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/aul_cmd.h DESTINATION include/aul)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/aul_app_com.h DESTINATION include/aul)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/aul.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/feature/preexec_list.txt DESTINATION ${SHARE_INSTALL_PREFIX}/aul )
INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/data/miregex DESTINATION ${SHARE_INSTALL_PREFIX}/aul )

# tool
add_subdirectory(tool)
