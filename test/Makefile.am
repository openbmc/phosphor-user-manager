AM_CPPFLAGS = -I$(top_srcdir)

# Run all 'check' test programs
TESTS = $(check_PROGRAMS)

test_CPPFLAGS = -Igtest \
                 $(GTEST_CPPFLAGS) \
                 $(AM_CPPFLAGS) \
                 $(PHOSPHOR_LOGGING_CFLAGS) \
                 $(SDBUSPLUS_CFLAGS)

test_CXXFLAGS = $(PTHREAD_CFLAGS)

test_LDFLAGS = -lgtest_main \
                -lgtest \
                $(PTHREAD_LIBS) \
                $(OESDK_TESTCASE_FLAGS) \
                $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
                $(PHOSPHOR_LOGGING_LIBS) \
                $(SDBUSPLUS_LIBS) \
                -lcrypt \
                -lstdc++fs

check_PROGRAMS = ldap_config_test
ldap_config_test_CPPFLAGS = $(test_CPPFLAGS)
ldap_config_test_CXXFLAGS = $(test_CXXFLAGS)
ldap_config_test_LDFLAGS  = $(test_LDFLAGS) \
                            -lldap \
                            -lgmock
ldap_config_test_SOURCES  = ldap_config_test.cpp utils_test.cpp
ldap_config_test_LDADD  = $(top_builddir)/phosphor-ldap-config/ldap_configuration.o $(top_builddir)/phosphor-ldap-config/utils.o

check_PROGRAMS += ldap_mapper_test
ldap_mapper_test_CPPFLAGS = $(test_CPPFLAGS)
ldap_mapper_test_CXXFLAGS = $(test_CXXFLAGS)
ldap_mapper_test_LDFLAGS  = $(test_LDFLAGS)
ldap_mapper_test_SOURCES  = ldap_mapper_test.cpp
ldap_mapper_test_LDADD  = $(top_builddir)/phosphor-ldap-mapper/ldap_mapper_entry.o \
                          $(top_builddir)/phosphor-ldap-mapper/ldap_mapper_mgr.o \
                          $(top_builddir)/phosphor-ldap-mapper/ldap_mapper_serialize.o
