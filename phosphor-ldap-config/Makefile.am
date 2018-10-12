sbin_PROGRAMS = phosphor-ldap-conf

noinst_HEADERS = ldap_configuration.hpp utils.hpp

phosphor_ldap_conf_SOURCES = \
                main.cpp \
                utils.cpp \
                ldap_configuration.cpp

phosphor_ldap_conf_LDFLAGS = $(SDBUSPLUS_LIBS) \
                             $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
                             $(PHOSPHOR_LOGGING_LIBS) \
                             -lstdc++fs \
                             -lldap

phosphor_ldap_conf_CXXFLAGS = $(SYSTEMD_CFLAGS) \
                              $(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
                              $(PHOSPHOR_LOGGING_CFLAGS) \
                              -flto
