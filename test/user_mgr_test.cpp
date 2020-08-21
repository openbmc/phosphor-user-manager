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

using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;

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
        return;
    }

    DbusUserObj createPrivilegeMapperDbusObject(void)
    {
        DbusUserObj test;
        return test;
    }

    DbusUserObj createLdapConfigObjectWithoutPrivilegeMapper(void)
    {
        DbusUserObj test;
        return test;
    }
};

TEST_F(TestUserMgr, ldapEntryDoesNotExist)
{
    std::string userName = "user";
    UserInfoMap userInfo;

    EXPECT_CALL(mockManager, getLdapGroupName(userName))
        .WillRepeatedly(Return(""));
    EXPECT_THROW(userInfo = mockManager.getUserInfo(userName), InternalFailure);
}
} // namespace user
} // namespace phosphor
