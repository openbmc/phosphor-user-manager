sbin_PROGRAMS = phosphor-user-manager

noinst_HEADERS = user.hpp user_mgr.hpp users.hpp

phosphor_user_manager_SOURCES = \
                user.cpp \
                mainapp.cpp \
                user_mgr.cpp \
                users.cpp

phosphor_user_manager_LDFLAGS = $(SDBUSPLUS_LIBS) \
                                $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
                                $(PHOSPHOR_LOGGING_LIBS) \
                                -lcrypt \
                                -lstdc++fs

phosphor_user_manager_CXXFLAGS = $(SYSTEMD_CFLAGS) \
                                 $(PHOSPHOR_DBUS_INTERFACES_CFLAGS) \
                                 $(PHOSPHOR_LOGGING_CFLAGS)
SUBDIRS = . test
