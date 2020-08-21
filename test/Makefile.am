AM_CPPFLAGS = -I$(top_srcdir)

# Run all 'check' test programs
TESTS = $(check_PROGRAMS)

cppflags = -Igtest \
           $(GTEST_CPPFLAGS) \
           $(AM_CPPFLAGS) \
           $(PHOSPHOR_LOGGING_CFLAGS) \
           $(SDBUSPLUS_CFLAGS)

cxxflags = $(PTHREAD_CFLAGS)

ldflags = -lgtest_main \
          -lgtest \
          $(PTHREAD_LIBS) \
          $(OESDK_TESTCASE_FLAGS) \
          $(PHOSPHOR_DBUS_INTERFACES_LIBS) \
          $(PHOSPHOR_LOGGING_LIBS) \
          $(SDBUSPLUS_LIBS) \
          -lcrypt \
          -lstdc++fs


check_PROGRAMS += user_mgr_test
user_mgr_test_CPPFLAGS = $(cppflags)
user_mgr_test_CXXFLAGS = $(cxxflags) $(GTEST_CPPFLAGS)
user_mgr_test_LDFLAGS  = $(ldflags) $(GTEST_LIBS) $(GMOCK_LIBS) -lgmock
user_mgr_test_SOURCES  = user_mgr_test.cpp
user_mgr_test_LDADD  = $(top_builddir)/user_mgr.o \
                       $(top_builddir)/users.o
