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
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/User/UserMgr/server.hpp>
#include <unordered_map>
#include "users.hpp"

namespace phosphor {
namespace user {

using UserMgrIface = sdbusplus::xyz::openbmc_project::User::server::UserMgr;

/** @class User
 *  @brief Responsible for managing a specific user account.
 */
class UserMgr : public UserMgrIface
{
  public:
    UserMgr() = delete;
    ~UserMgr() = default;
    UserMgr(const UserMgr &) = delete;
    UserMgr &operator=(const UserMgr &) = delete;
    UserMgr(UserMgr &&) = delete;
    UserMgr &operator=(UserMgr &&) = delete;

    /** @brief Constructs UserMgr object.
     *
     *  @param[in] bus  - sdbusplus handler
     *  @param[in] path - D-Bus path
     */
    UserMgr(sdbusplus::bus::bus &bus, const char *path);

    /** @brief add user method.
     *  This method creates a new user as requested
     *
     *  @param[in] userName - Name of the user which has to be created
     *  @param[in] groupNames - Group names list, to which user has to be added.
     * Separated by ,
     *                                         can be NULL too.
     *  @param[in] priv - Privilege of the user.
     */
    void addUser(std::string userName, std::vector<std::string> groupNames,
                 std::string priv) override;

    /** @brief delete user method.
     *  This method deletes the user as requested
     *
     *  @param[in] userName - Name of the user which has to be created
     */
    void deleteUser(std::string userName) override;

    /** @brief Update user groups & privilege.
     *  This method updates user groups & privilege
     *
     *  @param[in] userName - user name, for which update is requested
     *  @param[in] groupName - Group to be updated..
     *  @param[in] priv - Privilege to be updated.
     */
    void updateGroupsAndPriv(const std::string &userName,
                             const std::vector<std::string> &groups,
                             const std::string &priv);

  private:
    /** @brief sdbusplus handler */
    sdbusplus::bus::bus &bus;

    /** @brief object path */
    const std::string path;
    std::vector<std::string> privMgr = {"priv-admin", "priv-operator",
                                        "priv-user", "priv-callback"};
    std::vector<std::string> groupsMgr = {"web", "redfish", "ipmi", "ssh"};
    std::unordered_map<std::string, std::unique_ptr<phosphor::user::Users>>
        usersList;

    void getGroupUsers(const std::string &groupName,
                       std::vector<std::string> &userList);
    void getUserList(std::vector<std::string> &userList);
    void reset(void);
    void initUserObjects(void);
};

} // namespace user
} // namespace phosphor
