sbin_PROGRAMS = phosphor-user-manager

noinst_HEADERS = user.hpp

phosphor_user_manager_SOURCES = \
                user.cpp \
                mainapp.cpp

phosphor_user_manager_LDFLAGS = $(SDBUSPLUS_LIBS) \
                                $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
                                -lcrypt \
                                -lstdc++fs

phosphor_user_manager_CXXFLAGS = $(SYSTEMD_CFLAGS) \
                                 $(PHOSPHOR_DBUS_INTERFACES_CFLAGS)
SUBDIRS = . test
