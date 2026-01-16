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
    MOCK_METHOD(void, getShadowData, (const std::string&, struct spwd& spwd),
                (const, override));
    MOCK_METHOD(void, executeUserAdd, (const char*, const char*, bool, bool),
                (override));
    MOCK_METHOD(void, executeUserPasswordExpiration,
                (const char*, const long int, const long int),
                (const, override));

    friend class TestUserMgr;
};
class MockUser : public Users
{
  public:
    MockUser(sdbusplus::bus::bus& bus, const char* objPath,
             std::vector<std::string> groupNames, const std::string& priv,
             bool enabled, std::optional<uint64_t> passwordExpiration,
             UserMgr& parent) :
        Users(bus, objPath, groupNames, priv, enabled, passwordExpiration,
              parent)
    {}
    MOCK_METHOD0(createSecretKey, std::string());
    MOCK_METHOD0(clearSecretKey, void());
    MOCK_METHOD2(enableMultiFactorAuth,
                 void(MultiFactorAuthType type, bool value));
    MOCK_CONST_METHOD0(secretKeyIsValid, bool());
};

// Mock function for static clearGoogleAuthenticator
inline void clearGoogleAuthenticator(Users& /*thisp*/)
{
    // Mock implementation - does nothing
}
} // namespace user
} // namespace phosphor
