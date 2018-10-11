AM_CPPFLAGS = -I$(top_srcdir)

# Run all 'check' test programs
TESTS = $(check_PROGRAMS)

# Build/add utest to test suite
check_PROGRAMS = utest
utest_CPPFLAGS = -Igtest \
                 $(GTEST_CPPFLAGS) \
                 $(AM_CPPFLAGS) \
                 $(PHOSPHOR_LOGGING_CFLAGS) \
                 $(SDBUSPLUS_CFLAGS)

utest_CXXFLAGS = $(PTHREAD_CFLAGS)

utest_LDFLAGS = -lgtest_main \
                -lgtest \
                $(PTHREAD_LIBS) \
                $(OESDK_TESTCASE_FLAGS) \
                $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
                $(PHOSPHOR_LOGGING_LIBS) \
                $(SDBUSPLUS_LIBS) \
                -lcrypt \
                -lstdc++fs

utest_SOURCES = utest.cpp
utest_LDADD = $(top_builddir)/user.o

check_PROGRAMS += ldap_config_test
ldap_config_test_CPPFLAGS = $(utest_CPPFLAGS)
ldap_config_test_CXXFLAGS = $(utest_CXXFLAGS)
ldap_config_test_LDFLAGS  = $(utest_LDFLAGS) \
                            -lldap \
                            -lgmock
ldap_config_test_SOURCES  = ldap_config_test.cpp utils_test.cpp
ldap_config_test_LDADD  = $(top_builddir)/phosphor-ldap-config/ldap_configuration.o $(top_builddir)/phosphor-ldap-config/utils.o
