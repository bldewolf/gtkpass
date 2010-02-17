ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = gtkpass
gtkpass_SOURCES = src/gtkpass.c
gtkpass_CPPFLAGS = @GTK_CFLAGS@ -DICONDIR=\""$(datadir)/pixmaps"\"
gtkpass_LDADD = @GTK_LIBS@

desktopdir = $(datadir)/applications
desktop_DATA = gtkpass.desktop
pixmapdir = $(datadir)/pixmaps
pixmap_DATA = gtkpass.png
EXTRA_DIST =	$(desktop_DATA) \
		$(pixmap_DATA) \
		TODO \
		gtkpass.svg
