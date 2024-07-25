/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "config.h"

#include "users.hpp"

#include "totp.hpp"
#include "user_mgr.hpp"

#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <filesystem>
#include <fstream>
#include <map>
namespace phosphor
{
namespace user
{

using namespace phosphor::logging;
using InsufficientPermission =
    sdbusplus::xyz::openbmc_project::Common::Error::InsufficientPermission;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using NoResource =
    sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource;
using UnsupportedRequest =
    sdbusplus::xyz::openbmc_project::Common::Error::UnsupportedRequest;

using Argument = xyz::openbmc_project::Common::InvalidArgument;
constexpr auto authAppPath = "/usr/bin/google-authenticator";
constexpr auto secretKeyPath = "/home/{}/.google_authenticator";
constexpr auto secretKeyTempPath = "/home/{}/.google_authenticator.tmp";

/** @brief Constructs UserMgr object.
 *
 *  @param[in] bus  - sdbusplus handler
 *  @param[in] path - D-Bus path
 *  @param[in] groups - users group list
 *  @param[in] priv - user privilege
 *  @param[in] enabled - user enabled state
 *  @param[in] parent - user manager - parent object
 */
Users::Users(sdbusplus::bus_t& bus, const char* path,
             std::vector<std::string> groups, std::string priv, bool enabled,
             UserMgr& parent) :
    Interfaces(bus, path, Interfaces::action::defer_emit),
    userName(sdbusplus::message::object_path(path).filename()), manager(parent)
{
    UsersIface::userPrivilege(priv, true);
    UsersIface::userGroups(groups, true);
    UsersIface::userEnabled(enabled, true);

    this->emit_object_added();
}

/** @brief delete user method.
 *  This method deletes the user as requested
 *
 */
void Users::delete_(void)
{
    manager.deleteUser(userName);
}

/** @brief update user privilege
 *
 *  @param[in] value - User privilege
 */
std::string Users::userPrivilege(std::string value)
{
    if (value == UsersIface::userPrivilege())
    {
        return value;
    }
    manager.updateGroupsAndPriv(userName, UsersIface::userGroups(), value);
    return UsersIface::userPrivilege(value);
}

void Users::setUserPrivilege(const std::string& value)
{
    UsersIface::userPrivilege(value);
}

void Users::setUserGroups(const std::vector<std::string>& groups)
{
    UsersIface::userGroups(groups);
}

/** @brief list user privilege
 *
 */
std::string Users::userPrivilege(void) const
{
    return UsersIface::userPrivilege();
}

/** @brief update user groups
 *
 *  @param[in] value - User groups
 */
std::vector<std::string> Users::userGroups(std::vector<std::string> value)
{
    if (value == UsersIface::userGroups())
    {
        return value;
    }
    std::sort(value.begin(), value.end());
    manager.updateGroupsAndPriv(userName, value, UsersIface::userPrivilege());
    return UsersIface::userGroups(value);
}

/** @brief list user groups
 *
 */
std::vector<std::string> Users::userGroups(void) const
{
    return UsersIface::userGroups();
}

/** @brief lists user enabled state
 *
 */
bool Users::userEnabled(void) const
{
    return manager.isUserEnabled(userName);
}

void Users::setUserEnabled(bool value)
{
    UsersIface::userEnabled(value);
}

/** @brief update user enabled state
 *
 *  @param[in] value - bool value
 */
bool Users::userEnabled(bool value)
{
    if (value == UsersIface::userEnabled())
    {
        return value;
    }
    manager.userEnable(userName, value);
    return UsersIface::userEnabled(value);
}

/** @brief lists user locked state for failed attempt
 *
 **/
bool Users::userLockedForFailedAttempt(void) const
{
    return manager.userLockedForFailedAttempt(userName);
}

/** @brief unlock user locked state for failed attempt
 *
 * @param[in]: value - false - unlock user account, true - no action taken
 **/
bool Users::userLockedForFailedAttempt(bool value)
{
    if (value != false)
    {
        return userLockedForFailedAttempt();
    }
    else
    {
        return manager.userLockedForFailedAttempt(userName, value);
    }
}

/** @brief indicates if the user's password is expired
 *
 **/
bool Users::userPasswordExpired(void) const
{
    return manager.userPasswordExpired(userName);
}
bool changeFileOwnership(const std::string& filePath,
                         const std::string& userName)
{
    // Get the user ID
    struct passwd* pwd = getpwnam(userName.c_str());
    if (pwd == nullptr)
    {
        lg2::error("Failed to get user ID for user:{USER}", "USER", userName);
        return false;
    }
    // Change the ownership of the file
    if (chown(filePath.c_str(), pwd->pw_uid, pwd->pw_gid) != 0)
    {
        lg2::error("Ownership change error {PATH}", "PATH", filePath);
        return false;
    }
    return true;
}
bool Users::checkMfaStatus() const
{
    return (manager.enabled() != MultiFactorAuthType::None &&
            Interfaces::bypassedProtocol() == MultiFactorAuthType::None);
}
std::string Users::createSecretKey()
{
    if (!std::filesystem::exists(authAppPath))
    {
        lg2::error("No authenticator app found at {PATH}", "PATH", authAppPath);
        throw UnsupportedRequest();
    }
    std::string path = std::format(secretKeyTempPath, userName);
    /*
    -u no-rate-limit
    -W minimal-window
    -Q qr-mode (NONE, ANSI, UTF8)
    -t time-based
    -f force file
    -d disallow-reuse
    -C no-confirm no confirmation required for code provisioned
    */
    executeCmd(authAppPath, "-s", path.c_str(), "-u", "-W", "-Q", "NONE", "-t",
               "-f", "-d", "-C");
    if (!std::filesystem::exists(path))
    {
        lg2::error("Failed to create secret key for user {USER}", "USER",
                   userName);
        throw UnsupportedRequest();
    }
    std::ifstream file(path);
    if (!file.is_open())
    {
        lg2::error("Failed to open secret key file {PATH}", "PATH", path);
        throw UnsupportedRequest();
    }
    std::string secret;
    std::getline(file, secret);
    file.close();
    if (!changeFileOwnership(path, userName))
    {
        throw UnsupportedRequest();
    }
    return secret;
}
bool Users::verifyOTP(std::string otp)
{
    if (Totp::verify(getUserName(), otp) == PAM_SUCCESS)
    {
        // If MFA is enabled for the user register the secret key
        if (checkMfaStatus())
        {
            try
            {
                std::filesystem::rename(
                    std::format(secretKeyTempPath, getUserName()),
                    std::format(secretKeyPath, getUserName()));
            }
            catch (const std::filesystem::filesystem_error& e)
            {
                lg2::error("Failed to rename file: {CODE}", "CODE", e);
                return false;
            }
        }
        return true;
    }
    return false;
}

static void clearGoogleAuthenticator(Users& thisp)
{
    std::string path = std::format(secretKeyPath, thisp.getUserName());

    if (std::filesystem::exists(path))
    {
        std::filesystem::remove(path);
    }
};
static std::map<MultiFactorAuthType, std::function<void(Users&)>>
    mfaBypassHandlers{{MultiFactorAuthType::GoogleAuthenticator,
                       clearGoogleAuthenticator},
                      {MultiFactorAuthType::None, [](Users&) {}}};

MultiFactorAuthType
    Users::bypassedProtocol(MultiFactorAuthType value, bool skipSignal)
{
    auto iter = mfaBypassHandlers.find(value);
    if (iter != end(mfaBypassHandlers))
    {
        iter->second(*this);
    }
    return Interfaces::bypassedProtocol(value, skipSignal);
}

bool Users::secretKeyIsValid() const
{
    std::string path = std::format(secretKeyPath, getUserName());
    return std::filesystem::exists(path);
}

inline void googleAuthenticatorEnabled(Users& user, bool value)
{
    if (!value)
    {
        clearGoogleAuthenticator(user);
    }
}
static std::map<MultiFactorAuthType, std::function<void(Users&, bool)>>
    mfaEnableHandlers{{MultiFactorAuthType::GoogleAuthenticator,
                       googleAuthenticatorEnabled},
                      {MultiFactorAuthType::None, [](Users&, bool) {}}};

void Users::enableMultiFactorAuth(MultiFactorAuthType type, bool value)
{
    auto iter = mfaEnableHandlers.find(type);
    if (iter != end(mfaEnableHandlers))
    {
        iter->second(*this, value);
    }
}
bool Users::secretKeyGenerationRequired() const
{
    return checkMfaStatus() && !secretKeyIsValid();
}
void Users::clearSecretKey()
{
    if (!checkMfaStatus())
    {
        throw UnsupportedRequest();
    }
    clearGoogleAuthenticator(*this);
}

} // namespace user
} // namespace phosphor
