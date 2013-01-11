# required Python modules 
if COND_PYPCAP
  MAYBE_PYPCAP = pypcap
endif
if COND_PYDPKT
  MAYBE_PYDPKT = dpkt
endif
if COND_REGRESS
  MAYBE_REGRESS = regress
endif
SUBDIRS = . $(MAYBE_PYPCAP) $(MAYBE_PYDPKT) $(MAYBE_REGRESS)

AUTOMAKE_OPTIONS = foreign no-dependencies

########################################################################
##
## libhoneyd, the honeyd preload library. Wrapped around
## server applications to make them communicate through
## honeyd.
##
########################################################################

## Preload library
## This is how it should work but libtool is so broken
#pkglib_LTLIBRARIES = libhoneyd.la 
#libhoneyd_la_SOURCES = honeyd_overload.c atomicio.c fdpass.c fdpass.h
#libhoneyd_la_LDFLAGS = -module -export-dynamic -avoid-version

## Bad hack with help from marius@monkey.org to actually get this 
## working on Linux
LIBHONEYDFILES= honeyd_overload.lo atomicio.lo fdpass.lo
libhoneyd.so: $(LIBHONEYDFILES)
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o libtmp$@.la \
		-rpath $(libdir)/honeyd $(LIBHONEYDFILES) $(LIBS) $(LDFLAGS) \
		-module -avoid-version -nostdlib @LIBDL@
	rm -f libtmp$@.la tmp$@.so* $@
	cp .libs/libtmp$@.so $@ || cp .libs/libtmp$@ $@
	rm -f .libs/libtmp$@.*

libhoneyddir = $(libdir)/honeyd
libhoneyd_DATA = libhoneyd.so


# Configuration files for Honeyd
honeyddatadir = $(datadir)/honeyd
honeydlibdir = $(libdir)/honeyd
honeydincludedir = $(includedir)/honeyd
honeyddata_DATA = README nmap.assoc xprobe2.conf nmap-os-db config.sample \
		config.ethernet pf.os nmap-mac-prefixes

honeydplugins = @PLUGINS@
honeydpluginsdeclare = @PLUGINSDECLARE@

########################################################################
##
## Honeyd itself. It uses plugins, so we need to install a few header
## files that plugins can pick up when being built so that they know
## how to register etc.
##
########################################################################

bin_PROGRAMS = honeyd honeydctl honeydstats hsniff
honeyddata_PROGRAMS = $(SMTP_BIN) $(PROXY_BIN)
EXTRA_PROGRAMS = smtp proxy

# Install the header files in a separate subdirectory. Note that
# honeydincludedir is the directory reported to the user, who has to
# use that directory as an -I include directive with #include <honeyd/foo.h>.
# pkgincludedir includes the additional honeyd directory since that's
# where the headers are actually installed.
pkgincludedir = $(honeydincludedir)
pkginclude_HEADERS = hooks.h plugins.h plugins_config.h debug.h

honeyd_SOURCES	= honeyd.c command.c parse.y lex.l config.c personality.c \
	util.c ipfrag.c router.c tcp.c udp.c xprobe_assoc.c log.c \
	fdpass.c atomicio.c subsystem.c hooks.c plugins.c \
	plugins_config.c pool.c interface.c arp.c gre.c \
	honeyd.h personality.h ipfrag.h	router.h network.c network.h \
	tcp.h udp.h parse.h \
	xprobe_assoc.h subsystem.h fdpass.h hooks.h plugins.h \
	plugins_config.h template.h pool.h interface.h arp.h gre.h \
	log.h pfctl_osfp.c pf_osfp.c pfvar.h condition.c condition.h \
	osfp.c osfp.h ui.c ui.h ethernet.c ethernet.h \
	parser.h tagging.c tagging.h stats.c stats.h \
	dhcpclient.c dhcpclient.h rrdtool.c rrdtool.h \
	histogram.c histogram.h untagging.c untagging.h

honeyd_DEPENDENCIES = @PYEXTEND@ @LIBOBJS@
honeyd_LDADD = @PYEXTEND@ @LIBOBJS@ @PYTHONLIB@ @EVENTLIB@ @PCAPLIB@ \
	@DNETLIB@ @ZLIB@ @PLUGINLIB@ -lm

# Allow plugins to use honeyd's functions:
honeyd_LDFLAGS = -export-dynamic 

# Honeyd stats collector
#
honeydstats_SOURCES = honeydstats.c honeydstats.h \
	honeydstats_main.c tagging.c tagging.h \
	stats.c stats.h util.c histogram.c histogram.h analyze.c analyze.h \
	untagging.c untagging.h filter.c filter.h keycount.c keycount.h
honeydstats_LDADD = @LIBOBJS@ @DNETLIB@ @EVENTLIB@ @ZLIB@
honeydstats_CPPFLAGS = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @ZINC@
honeydstats_CFLAGS = -O0 -Wall

#
# Honeyd stats sniffer
#

hsniff_SOURCES = hsniff.c hsniff.h tagging.c tagging.h \
	stats.c stats.h util.c util.h hooks.c hooks.h interface.c interface.h \
	pfctl_osfp.c pf_osfp.c pfvar.h osfp.c osfp.h network.c network.h
hsniff_LDADD = @LIBOBJS@ @PCAPLIB@ @DNETLIB@ @EVENTLIB@ @ZLIB@
hsniff_CPPFLAGS = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@EVENTINC@ @PCAPINC@ @DNETINC@ @ZINC@
hsniff_CFLAGS = -O2 -Wall -DPATH_HONEYDDATA="\"$(honeyddatadir)\""

#
# Honeyd control application
#
honeydctl_SOURCES = honeydctl.c
honeydctl_LDADD = @LIBOBJS@ @EDITLIB@ @LIBCURSES@
honeydctl_CPPFLAGS = @EDITINC@
honeydctl_CFLAGS = -O2 -Wall

CFLAGS	= -O2 -Wall -g \
	-DPATH_HONEYDINCLUDE="\"$(honeydincludedir)\"" \
	-DPATH_HONEYDDATA="\"$(honeyddatadir)\"" \
	-DPATH_HONEYDLIB="\"$(honeydlibdir)\"" \
	-DHONEYD_PLUGINS_DECLARE="$(honeydpluginsdeclare)" \
	-DHONEYD_PLUGINS="$(honeydplugins)" \
	-DPATH_RRDTOOL="\"$(PATH_RRDTOOL)\"" \
	-D_GNU_SOURCE

INCLUDES = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@PYTHONINC@ @EVENTINC@ @PCAPINC@ @DNETINC@ @ZINC@

########################################################################
## Simple subsystems to be used with Honeyd
########################################################################

smtp_SOURCES = subsystems/smtp.c subsystems/smtp.h subsystems/smtp_main.c \
	subsystems/smtp_messages.h atomicio.c \
	util.c util.h honeyd_overload.h

smtp_LDADD = @LIBOBJS@ @EVENTLIB@ @DNETLIB@ @PCAPLIB@ @PCRELIB@
smtp_CPPFLAGS = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @PCREINC@
smtp_CFLAGS = -O2 -Wall

proxy_SOURCES = subsystems/proxy.c subsystems/proxy.h subsystems/proxy_main.c \
	subsystems/proxy_messages.h subsystems/smtp.c subsystems/smtp.h \
	subsystems/smtp_messages.h atomicio.c \
	util.c util.h honeyd_overload.h

proxy_LDADD = @LIBOBJS@ @EVENTLIB@ @DNETLIB@ @PCAPLIB@ @PCRELIB@
proxy_CPPFLAGS = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @PCREINC@
proxy_CFLAGS = -O2 -Wall

########################################################################
##
## Miscellaneous stuff -- files we need to include in the package,
## manpage, yacc/lex stuff etc.
##
########################################################################

man_MANS = honeyd.8 honeydctl.1

WEBDIR_FILES = webserver/htmltmpl.py \
	webserver/htdocs/images/logo.gif webserver/htdocs/images/edit.gif \
	webserver/htdocs/images/delete.gif webserver/htdocs/images/add.gif \
	webserver/htdocs/images/arrow_down.gif \
	webserver/htdocs/images/arrow_right.gif \
	webserver/htdocs/images/google_logo.gif \
	webserver/htdocs/templates/inc/header.tmpl \
	webserver/htdocs/templates/inc/footer.tmpl \
	webserver/htdocs/templates/inc/main.tmpl \
	webserver/htdocs/templates/inc/nav.tmpl \
	webserver/htdocs/templates/config_ip.tmpl \
	webserver/htdocs/templates/index.tmpl \
	webserver/htdocs/templates/status_connections.tmpl \
	webserver/htdocs/templates/status_stats.tmpl \
	webserver/htdocs/graphs/traffic_daily.gif \
	webserver/htdocs/graphs/traffic_hourly.gif \
	webserver/htdocs/index.py \
	webserver/htdocs/styles/layout.css \
	webserver/htdocs/config.py \
	webserver/support.py \
	webserver/server.py

# Automake sucks - but that's ok
PYTHON_FILES = pypcap/CHANGES pypcap/pcap_ex.c \
	pypcap/test.py pypcap/LICENSE pypcap/pcap_ex.h \
	pypcap/testsniff.py pypcap/Makefile.am pypcap/Makefile.in \
	pypcap/pcap.c pypcap/setup.py \
	pypcap/README pypcap/pcap.pyx pypcap/test.pcap \
	dpkt/AUTHORS dpkt/dpkt/gre.py dpkt/dpkt/ppp.py \
	dpkt/CHANGES dpkt/HACKING dpkt/dpkt/hsrp.py dpkt/dpkt/rpc.py \
	dpkt/LICENSE dpkt/Makefile dpkt/dpkt/http.py dpkt/dpkt/smb.py \
	dpkt/README dpkt/dpkt/__init__.py dpkt/dpkt/icmp.py dpkt/dpkt/stp.py \
	dpkt/dpkt/ah.py dpkt/dpkt/icmp6.py dpkt/dpkt/stun.py \
	dpkt/dpkt/aim.py dpkt/dpkt/igmp.py dpkt/dpkt/tcp.py \
	dpkt/dpkt/arp.py dpkt/dpkt/ip.py dpkt/dpkt/telnet.py \
	dpkt/dpkt/asn1.py dpkt/dpkt/ip6.py dpkt/dpkt/tftp.py \
	dpkt/dpkt/cdp.py dpkt/dpkt/ipx.py dpkt/dpkt/tns.py \
	dpkt/dpkt/dhcp.py dpkt/dpkt/loopback.py dpkt/dpkt/udp.py \
	dpkt/dpkt/dns.py dpkt/dpkt/netbios.py dpkt/dpkt/vrrp.py \
	dpkt/dpkt/dpkt.py dpkt/dpkt/netflow.py dpkt/dpkt/yahoo.py \
	dpkt/dpkt/dtp.py dpkt/dpkt/ospf.py dpkt/examples/dnsping.py \
	dpkt/dpkt/esp.py dpkt/dpkt/pcap.py dpkt/examples/ping.py \
	dpkt/setup.py \
	dpkt/dpkt/ethernet.py dpkt/dpkt/pim.py dpkt/tests/test-perf.py \
	dpkt/tests/test-perf2.py

# TODO: Fix this, half the scripts are missing and this will probably break gzipping
EXTRA_DIST = $(man_MANS) $(WEBDIR_FILES) $(PYTHON_FILES)		  \
	acconfig.h $(honeyddata_DATA) LICENSE sha1.c			  \
	compat/sys/tree.h compat/sys/queue.h compat/err.h compat/sha1.h	  \
	compat/libdnet/dnet.h compat/getopt.h				  \
	honeyd_overload.c pyextend.c pyextend.h \
	pydataprocessing.c pydataprocessing.h \
	pydatahoneyd.c pydatahoneyd.h scripts

install-data-local:
	$(mkdir_p) "$(DESTDIR)$(honeyddatadir)"
	(cd $(top_srcdir) && tar -cf - $(top_srcdir)/webserver) | \
	(cd $(DESTDIR)$(honeyddatadir) && tar -xf -)
	find $(DESTDIR)$(honeyddatadir)/webserver -type f | xargs chmod a+r
	find $(DESTDIR)$(honeyddatadir)/webserver -type d | xargs chmod a+xr
	(cd $(top_srcdir) && tar -cf - $(top_srcdir)/scripts) | \
	(cd $(DESTDIR)$(honeyddatadir) && tar -xf -)

CLEANFILES = *.so
DISTCLEANFILES = *~

LEX_OUTPUT_ROOT = lex.hyd
LFLAGS  = -Phyd
YFLAGS  = -d
