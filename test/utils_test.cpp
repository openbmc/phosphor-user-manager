#include "phosphor-ldap-config/utils.hpp"

#include <ldap.h>
#include <netinet/in.h>

#include <gtest/gtest.h>

namespace phosphor
{
namespace ldap
{
constexpr auto ldapScheme = "ldap";
constexpr auto ldapsScheme = "ldaps";

class TestUtil : public testing::Test
{
  public:
    TestUtil()
    {
        // Empty
    }
};

TEST_F(TestUtil, URIValidation)
{
    std::string ipAddress = "ldap://0.0.0.0";
    EXPECT_EQ(true, isValidLDAPURI(ipAddress.c_str(), ldapScheme));

    ipAddress = "ldap://9.3.185.83";
    EXPECT_EQ(true, isValidLDAPURI(ipAddress.c_str(), ldapScheme));

    ipAddress = "ldaps://9.3.185.83";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapScheme));

    ipAddress = "ldap://9.3.a.83";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapScheme));

    ipAddress = "ldap://9.3.185.a";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapScheme));

    ipAddress = "ldap://x.x.x.x";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapScheme));

    ipAddress = "ldaps://0.0.0.0";
    EXPECT_EQ(true, isValidLDAPURI(ipAddress.c_str(), ldapsScheme));

    ipAddress = "ldap://0.0.0.0";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapsScheme));

    ipAddress = "ldaps://9.3.185.83";
    EXPECT_EQ(true, isValidLDAPURI(ipAddress.c_str(), ldapsScheme));

    ipAddress = "ldap://9.3.185.83";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapsScheme));

    ipAddress = "ldaps://9.3.185.83";
    EXPECT_EQ(true, isValidLDAPURI(ipAddress.c_str(), ldapsScheme));

    ipAddress = "ldaps://9.3.185.a";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapsScheme));

    ipAddress = "ldaps://9.3.a.83";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapsScheme));

    ipAddress = "ldaps://x.x.x.x";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapsScheme));

    ipAddress = "ldap://9.3.185.83:70000";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapScheme));

    ipAddress = "ldap://9.3.185.83:-3";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapScheme));

    ipAddress = "ldap://9.3.185.83:221";
    EXPECT_EQ(true, isValidLDAPURI(ipAddress.c_str(), ldapScheme));

    ipAddress = "ldap://9.3.185.83:0";
    EXPECT_EQ(false, isValidLDAPURI(ipAddress.c_str(), ldapScheme));
}
} // namespace ldap
} // namespace phosphor
