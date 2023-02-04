plistdir	= $(datadir)/nabud/launchd
plist_DATA	= nabud.plist

CLEANFILES	= $(plist_DATA)

nabud.plist: nabud.plist.in
	sed "s,XXXsbindirXXX,$(sbindir),g" < nabud.plist.in > nabud.plist
