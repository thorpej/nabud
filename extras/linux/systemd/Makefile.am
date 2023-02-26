systemddir	= $(datadir)/nabud/systemd
systemd_DATA	= nabud.service

CLEANFILES	= $(systemd_DATA)

nabud.service: nabud.service.in
	sed "s,XXXsbindirXXX,$(sbindir),g" < nabud.service.in > nabud.service
