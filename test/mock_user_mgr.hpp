#include "user_mgr.hpp"

#include <gmock/gmock.h>

namespace phosphor
{
namespace user
{

constexpr auto objpath = "/dummy/user";

class MockManager : public UserMgr
{
  public:
    MockManager(sdbusplus::bus_t& bus, const char* path) : UserMgr(bus, path) {}

    MOCK_METHOD0(getPrivilegeMapperObject, DbusUserObj());
    MOCK_METHOD1(userLockedForFailedAttempt, bool(const std::string& userName));
    MOCK_METHOD1(userPasswordExpired, bool(const std::string& userName));
    MOCK_METHOD1(isUserEnabled, bool(const std::string& userName));
    MOCK_CONST_METHOD1(getPrimaryGroup, gid_t(const std::string& userName));
    MOCK_CONST_METHOD3(isGroupMember,
                       bool(const std::string& userName, gid_t primaryGid,
                            const std::string& groupName));

    friend class TestUserMgr;
};
class MockUser : public Users
{
  public:
    MockUser(sdbusplus::bus_t& bus, const char* objPath,
             std::vector<std::string> groupNames, const std::string& priv,
             bool enabled, UserMgr& parent) :
        Users(bus, objPath, groupNames, priv, enabled, parent)
    {}
    MOCK_METHOD0(createSecretKey, std::string());
};
} // namespace user
} // namespace phosphor
