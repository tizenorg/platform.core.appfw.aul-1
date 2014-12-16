INCLUDE(GNUInstallDirs)

SET(WAYLAND_SCANNER "wayland-scanner")

add_custom_command(OUTPUT aul-protocol.c PRE_BUILD
	COMMAND ${WAYLAND_SCANNER} code < aul.xml > aul-protocol.c)
add_custom_command(OUTPUT aul-server-protocol.h PRE_BUILD
	COMMAND ${WAYLAND_SCANNER} server-header < aul.xml > aul-server-protocol.h)

pkg_check_modules(plugpkgs REQUIRED wayland-server weston pixman-1 xkbcommon)

FOREACH(flag ${plugpkgs_CFLAGS})
        SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)
FOREACH(flag ${plugpkgs_LDFLAGS})
        SET(EXTRA_LDFLAGS "${EXTRA_LDFLAGS} ${flag}")
ENDFOREACH(flag)

add_library(aul-plugin MODULE aul-plugin.c aul-protocol.c aul-server-protocol.h)
set_target_properties(aul-plugin PROPERTIES COMPILE_FLAGS "${EXTRA_CFLAGS}")
set_target_properties(aul-plugin PROPERTIES LINK_FLAGS "${EXTRA_LDFLAGS}")
set_target_properties(aul-plugin PROPERTIES PREFIX "")

install(TARGETS aul-plugin DESTINATION LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/weston)
