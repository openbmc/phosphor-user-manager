#include "phosphor-ldap-config/utils.hpp"
#include <netinet/in.h>
#include <gtest/gtest.h>
#include <ldap.h>

namespace phosphor
{
namespace ldap
{

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
    std::string ipaddress = "ldap://0.0.0.0";
    EXPECT_EQ(true, isValidLDAPURI(ipaddress.c_str()));

    ipaddress = "ldap://9.3.185.83";
    EXPECT_EQ(true, isValidLDAPURI(ipaddress.c_str()));

    ipaddress = "ldaps://9.3.185.83";
    EXPECT_EQ(false, isValidLDAPURI(ipaddress.c_str()));

    ipaddress = "ldap://9.3.a.83";
    EXPECT_EQ(false, isValidLDAPURI(ipaddress.c_str()));

    ipaddress = "ldap://9.3.185.a";
    EXPECT_EQ(false, isValidLDAPURI(ipaddress.c_str()));

    ipaddress = "ldap://x.x.x.x";
    EXPECT_EQ(false, isValidLDAPURI(ipaddress.c_str()));

    ipaddress = "ldaps://0.0.0.0";
    EXPECT_EQ(true, isValidLDAPSURI(ipaddress.c_str()));

    ipaddress = "ldap://0.0.0.0";
    EXPECT_EQ(false, isValidLDAPSURI(ipaddress.c_str()));

    ipaddress = "ldaps://9.3.185.83";
    EXPECT_EQ(true, isValidLDAPSURI(ipaddress.c_str()));

    ipaddress = "ldap://9.3.185.83";
    EXPECT_EQ(false, isValidLDAPSURI(ipaddress.c_str()));

    ipaddress = "ldaps://9.3.185.83";
    EXPECT_EQ(true, isValidLDAPSURI(ipaddress.c_str()));

    ipaddress = "ldaps://9.3.185.a";
    EXPECT_EQ(false, isValidLDAPSURI(ipaddress.c_str()));

    ipaddress = "ldaps://9.3.a.83";
    EXPECT_EQ(false, isValidLDAPSURI(ipaddress.c_str()));

    ipaddress = "ldaps://x.x.x.x";
    EXPECT_EQ(false, isValidLDAPSURI(ipaddress.c_str()));
}
} // namespace ldap
} // namespace phosphor
