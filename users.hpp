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
#pragma once
#include "json_serializer.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Object/Delete/server.hpp>
#include <xyz/openbmc_project/User/Attributes/server.hpp>
#include <xyz/openbmc_project/User/MultiFactorAuthConfiguration/server.hpp>
#include <xyz/openbmc_project/User/TOTPAuthenticator/server.hpp>

#include <optional>

namespace phosphor
{
namespace user
{

namespace base = sdbusplus::xyz::openbmc_project;
using UsersIface = base::User::server::Attributes;

using TOTPAuthenticatorIface = base::User::server::TOTPAuthenticator;
using DeleteIface = base::Object::server::Delete;
using Interfaces = sdbusplus::server::object_t<UsersIface, DeleteIface,
                                               TOTPAuthenticatorIface>;
using MultiFactorAuthType = sdbusplus::common::xyz::openbmc_project::user::
    MultiFactorAuthConfiguration::Type;
using MultiFactorAuthConfiguration =
    sdbusplus::common::xyz::openbmc_project::user::MultiFactorAuthConfiguration;
// Place where all user objects has to be created
constexpr auto usersObjPath = "/xyz/openbmc_project/user";

class UserMgr; // Forward declaration for UserMgr.

/** @class Users
 *  @brief Lists User objects and it's properties
 */
class Users : public Interfaces
{
  public:
    Users() = delete;
    ~Users();
    Users(const Users&) = delete;
    Users& operator=(const Users&) = delete;
    Users(Users&&) = delete;
    Users& operator=(Users&&) = delete;

    /** @brief Constructs Users object.
     *
     *  @param[in] bus  - sdbusplus handler
     *  @param[in] path - D-Bus path
     *  @param[in] groups - users group list
     *  @param[in] priv - users privilege
     *  @param[in] enabled - user enabled state
     *  @param[in] passwordExpiration - user password expiration Epoch time
     *  @param[in] parent - user manager - parent object
     */
    Users(sdbusplus::bus_t& bus, const char* path,
          std::vector<std::string> groups, std::string priv, bool enabled,
          std::optional<uint64_t> passwordExpiration, UserMgr& parent);

    /** @brief delete user method.
     *  This method deletes the user as requested
     *
     */
    void delete_(void) override;

    /** @brief update user privilege
     *
     *  @param[in] value - User privilege
     */
    std::string userPrivilege(std::string value) override;

    void setUserPrivilege(const std::string& value);

    void setUserGroups(const std::vector<std::string>& groups);

    /** @brief lists user privilege
     *
     */
    std::string userPrivilege(void) const override;

    /** @brief update user groups
     *
     *  @param[in] value - User groups
     */
    std::vector<std::string> userGroups(
        std::vector<std::string> value) override;

    /** @brief list user groups
     *
     */
    std::vector<std::string> userGroups(void) const override;

    /** @brief lists user enabled state
     *
     */
    bool userEnabled(void) const override;

    void setUserEnabled(bool value);

    /** @brief update user enabled state
     *
     *  @param[in] value - bool value
     */
    bool userEnabled(bool value) override;

    /** @brief lists user locked state for failed attempt
     *
     **/
    bool userLockedForFailedAttempt(void) const override;

    /** @brief unlock user locked state for failed attempt
     *
     * @param[in]: value - false - unlock user account, true - no action taken
     **/
    bool userLockedForFailedAttempt(bool value) override;

    /** @brief indicates if the user's password is expired
     *
     **/
    bool userPasswordExpired(void) const override;

    std::string getUserName() const
    {
        return userName;
    }
    bool secretKeyIsValid() const override;
    std::string createSecretKey() override;
    bool verifyOTP(std::string otp) override;
    bool secretKeyGenerationRequired() const override;
    void clearSecretKey() override;
    MultiFactorAuthType bypassedProtocol(MultiFactorAuthType value,
                                         bool skipSignal) override;
    void enableMultiFactorAuth(MultiFactorAuthType type, bool value);
    void load(JsonSerializer& serializer);

    /** @brief user password expiration
     *
     * Password expiration is date time when the user password expires. The time
     * is the Epoch time, number of seconds since 1 Jan 1970 00::00::00 UTC.
     * When zero value is returned, it means that password does not expire. When
     * maximum value is returned, it means that password expiration is not set.
     *
     **/
    uint64_t passwordExpiration() const override;

    /** @brief update user password expiration
     *
     * Password expiration is date time when the user password expires. The time
     * is the Epoch time, number of seconds since 1 Jan 1970 00::00::00 UTC.
     * When zero value is provided, it means that password does not expire.
     *
     **/
    uint64_t passwordExpiration(uint64_t value) override;

  private:
    bool checkMfaStatus() const;
    std::string userName;
    UserMgr& manager;
};

} // namespace user
} // namespace phosphor
