#include "mock_user_mgr.hpp"
#include <xyz/openbmc_project/User/Common/error.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <gtest/gtest.h>
#include <exception>

namespace phosphor
{
namespace user
{

using ::testing::Return;

using UserNamePrivFail =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNamePrivFail;

class TestUserMgr : public testing::Test
{
  public:
    sdbusplus::bus::bus bus;
    MockManager mockManager;

    TestUserMgr() :
        bus(sdbusplus::bus::new_default()), mockManager(bus, objpath)
    {
    }

    void createLocalUser(const std::string &userName,
                         std::vector<std::string> groupNames,
                         const std::string &priv, bool enabled)
    {
        std::string userObj = std::string(usersObjPath) + "/" + userName;
        mockManager.usersList.emplace(
            userName, std::move(std::make_unique<phosphor::user::Users>(
                          mockManager.bus, userObj.c_str(), groupNames, priv,
                          enabled, mockManager)));
    }

    DbusUserObj createPrivilegeMapperDbusObject(void)
    {
        DbusUserObj object;
        DbusUserObjValue objValue;
        DbusUserObjPath object_path("/xyz/openbmc_project/user/ldap");
        DbusUserPropVariant group("ldapGroup");
        DbusUserPropVariant priv("priv-admin");
        DbusUserObjProperties properties = {std::make_pair("GroupName", group),
                                            std::make_pair("Privilege", priv)};
        std::string interface = "xyz.openbmc_project.User.PrivilegeMapperEntry";

        objValue.emplace(interface, properties);
        object.emplace(object_path, objValue);

        return object;
    }
};

TEST_F(TestUserMgr, localUser)
{
    UserInfoMap userInfo;
    std::string userName = "testUser";
    std::string privilege = "priv-admin";
    std::vector<std::string> groups{"testGroup"};
    // Create local user
    createLocalUser(userName, groups, privilege, true);
    EXPECT_CALL(mockManager, userLockedForFailedAttempt(userName)).Times(1);
    userInfo = mockManager.getUserInfo(userName);

    EXPECT_EQ(privilege, std::get<std::string>(userInfo["UserPrivilege"]));
    EXPECT_EQ(groups,
              std::get<std::vector<std::string>>(userInfo["UserGroups"]));
    EXPECT_EQ(true, std::get<bool>(userInfo["UserEnabled"]));
}

TEST_F(TestUserMgr, ldapUserWithPrivMapper)
{
    UserInfoMap userInfo;
    std::string userName = "ldapUser";
    std::string ldapGroup = "ldapGroup";

    EXPECT_CALL(mockManager, getLdapGroupName(userName))
        .WillRepeatedly(Return(ldapGroup));
    // Create privilege mapper dbus object
    DbusUserObj object = createPrivilegeMapperDbusObject();
    EXPECT_CALL(mockManager, getPrivilegeMapperObject())
        .WillRepeatedly(Return(object));
    userInfo = mockManager.getUserInfo(userName);
    EXPECT_EQ("priv-admin", std::get<std::string>(userInfo["UserPrivilege"]));
}

TEST_F(TestUserMgr, ldapUserWithoutPrivMapper)
{
    UserInfoMap userInfo;
    std::string userName = "ldapUser";
    std::string ldapGroup = "ldapGroup";
    DbusUserObj object;

    EXPECT_CALL(mockManager, getLdapGroupName(userName))
        .WillRepeatedly(Return(ldapGroup));
    EXPECT_CALL(mockManager, getPrivilegeMapperObject())
        .WillRepeatedly(Return(object));
    userInfo = mockManager.getUserInfo(userName);
    EXPECT_EQ("", std::get<std::string>(userInfo["UserPrivilege"]));

}
} // namespace user
} // namespace phosphor
