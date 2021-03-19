bin_PROGRAMS = phosphor-user-manager

noinst_HEADERS = user_mgr.hpp users.hpp

phosphor_user_manager_SOURCES = \
                mainapp.cpp \
                user_mgr.cpp \
                users.cpp

phosphor_user_manager_LDFLAGS = $(SDBUSPLUS_LIBS) \
                                $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
                                $(PHOSPHOR_LOGGING_LIBS) \
                                $(BOOST_CPPFLAGS) \
                                -lcrypt \
                                -lstdc++fs

phosphor_user_manager_CXXFLAGS = $(SYSTEMD_CFLAGS) \
                                 $(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
                                 $(PHOSPHOR_LOGGING_CFLAGS) \
                                 $(BOOST_CPPFLAGS) \
                                 -DBOOST_ALL_NO_LIB \
                                 -DBOOST_SYSTEM_NO_DEPRECATED \
                                 -DBOOST_ERROR_CODE_HEADER_ONLY

certmgrenvdir=$(datadir)/phosphor-certificate-manager
systemdsystemunit_DATA = phosphor-certificate-manager@.service
dbuspolicy_DATA = phosphor-nslcd-cert-config.conf
certmgrenv_DATA = nslcd
SYSTEM_UNIT_ALIASES = \
	../phosphor-certificate-manager@.service multi-user.target.wants/phosphor-certificate-manager@nslcd.service

SUBDIRS = . phosphor-ldap-mapper phosphor-ldap-config test

install-aliases-hook:
	set -- $(SYSTEM_UNIT_ALIASES) && \
	  dir=$(systemdsystemunitdir) && $(install-aliases)

define install-aliases
  while [ -n "$$1" ]; do \
	$(MKDIR_P) `dirname $(DESTDIR)$$dir/$$2` && \
	rm -f $(DESTDIR)$$dir/$$2 && \
	$(LN_S) $$1 $(DESTDIR)$$dir/$$2 && \
	shift 2 || exit $$?; \
  done
endef

INSTALL_DATA_HOOKS = \
	install-aliases-hook

install-data-hook: $(INSTALL_DATA_HOOKS)
