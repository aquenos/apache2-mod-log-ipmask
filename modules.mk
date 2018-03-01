mod_log_ipmask.la: mod_log_ipmask.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_log_ipmask.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_log_ipmask.la
