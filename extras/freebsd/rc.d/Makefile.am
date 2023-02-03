rcdir		= $(datadir)/nabud/rc.d
rc_SCRIPTS	= nabud

CLEANFILES	= $(rc_SCRIPTS)

nabud: nabud.in
	sed "s,XXXsbindirXXX,$(sbindir),g" < nabud.in > nabud
