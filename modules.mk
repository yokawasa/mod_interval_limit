MOD_LIMIT_PERIODIC = mod_interval_limit memcached_funcs

HEADER = memcached_funcs.h commons.h

${MOD_LIMIT_PERIODIC:=.slo}: ${HEADER}
${MOD_LIMIT_PERIODIC:=.lo}: ${HEADER}
${MOD_LIMIT_PERIODIC:=.o}: ${HEADER}

mod_interval_limit.la: ${MOD_LIMIT_PERIODIC:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version ${MOD_LIMIT_PERIODIC:=.lo}

DISTCLEAN_TARGETS = modules.mk

shared =  mod_interval_limit.la
