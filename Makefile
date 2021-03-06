##
##  Makefile -- Build procedure for sample interval_limit Apache module
##  Autogenerated via ``apxs -n interval_limit -g''.
##

ap_basedir=/home/apache-2.2.2
builddir=.
top_srcdir=$(ap_basedir)
top_builddir=$(ap_basedir)
include $(ap_basedir)/build/special.mk

#   the used tools
APXS=$(ap_basedir)/bin/apxs
APACHECTL=$(ap_basedir)/bin/apachectl

INCLUDES=-I/usr/local/include -I/usr/include
SH_LIBS=-L/usr/local/lib -lmemcached
#   the default target
all: local-shared-build

#   install the shared object file into Apache
install: install-modules-yes

#   cleanup
clean:
	-rm -f *.o *.lo *.slo *.la *~ .libs
#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: stop install start

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop

