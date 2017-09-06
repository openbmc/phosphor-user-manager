/**
 * Copyright © 2017 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <shadow.h>
#include <array>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/User/Account/Password/error.hpp>
#include "elog-errors.hpp"
#include "user.hpp"
#include "config.h"
namespace phosphor
{
namespace user
{

// Update user password
void Account::update(std::string oldPassword,
                     std::string newPassword)
{
    using namespace phosphor::logging;
    using UpdateFailure = sdbusplus::xyz::openbmc_project::
                               User::Account::Password::Error::UpdateFailure;
    using InvalidPassword = sdbusplus::xyz::openbmc_project::
                               User::Account::Password::Error::InvalidPassword;

    // Needed by getspnam_r
    struct spwd shdp;
    struct spwd* pshdp;

    // This should be fine even if SHA512 is used.
    std::array<char,1024> buffer{};

    // rewind to the start of shadow entry
    setspent();

    // 1: Read /etc/shadow for the user
    auto r = getspnam_r(user.c_str(), &shdp, buffer.data(),
                        buffer.max_size(), &pshdp);
    if (r < 0)
    {
        elog<UpdateFailure>(
            phosphor::logging::xyz::openbmc_project::User::Account::
                Password::UpdateFailure::ERRNO(errno),
            phosphor::logging::xyz::openbmc_project::User::Account::
                Password::UpdateFailure::DESCRIPTION(
                    "Unable to read shadow password entry for user"));
    }

    // 2: Parse and get [algo, salt, hash]
    auto entry = getShadowFields(shdp.sp_pwdp);

    // 3: Validate old password against what is in /etc/shadow
    if (!validatePassword(oldPassword, entry))
    {
        elog<InvalidPassword>(
            phosphor::logging::xyz::openbmc_project::User::Account::
                Password::InvalidPassword::PASSWORD(oldPassword.c_str()));
    }

    // Done reading
    endspent();

    // Old password was valid. So update the new one
    auto fp = fopen(SHADOW_FILE, "r+");
    if (fp == NULL)
    {
        elog<UpdateFailure>(
            phosphor::logging::xyz::openbmc_project::User::Account::
                Password::UpdateFailure::ERRNO(errno),
            phosphor::logging::xyz::openbmc_project::User::Account::
                Password::UpdateFailure::DESCRIPTION(
                    "Unable to open shadow password file"));
    }

    // Generate a random string from set [A-Za-z0-9./]
    std::string salt;
    salt.resize(10);
    std::generate_n(salt.begin(), salt.size(), randomChar);

    // Update shadow password pointer with hash
    auto saltString = getSaltString(std::get<0>(entry), salt);
    auto hash = generateHash(newPassword, saltString);
    shdp.sp_pwdp = const_cast<char*>(hash.c_str());

    // Apply
    putspent(&shdp, fp);
    fclose(fp);

    return;
}

// Returns a random character in set [A-Za-z0-9./]
char Account::randomChar()
{
    // Needed per crypt(3)
    std::string set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
                      "lmnopqrstuvwxyz0123456789./";
    return set.at(std::rand() % set.size());
}

// Extract crypto, salt and hash
shadowFields Account::getShadowFields(char* spPwdp)
{
    std::string algo = std::strtok(spPwdp, "$");
    std::string salt = std::strtok(NULL, "$");
    std::string hash = std::strtok(NULL, "$");

    return std::make_tuple(algo, salt, hash);
}

// Returns specific format of salt string
std::string Account::getSaltString(const std::string& crypt,
                                   const std::string& salt)
{
    return '$' + crypt + '$' + salt + '$';
}

// Given a password and salt, generates hash
std::string Account::generateHash(const std::string& password,
                                  const std::string& salt)
{
    return crypt(password.c_str(), salt.c_str());
}

// Validate password against what is in /etc/shadow
bool Account::validatePassword(const std::string& password,
                               const shadowFields& entry)
{
    // Need to pass $<crypt_number>$salt$ to generate hash using salt
    // Generated hash contains crypt,salt and the password hash combined
    auto saltString = getSaltString(std::get<0>(entry),
                                    std::get<1>(entry));

    auto combined = saltString + std::get<2>(entry);
    if (combined != generateHash(password, saltString))
    {
        return false;
    }
    return true;
}

} // namespace user
} // namespace phosphor
