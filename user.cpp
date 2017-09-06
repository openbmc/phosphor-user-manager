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
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <shadow.h>
#include <array>
#include <phosphor-logging/elog.hpp>
#include <xyz/openbmc_project/User/Password/error.hpp>
#include "elog-errors.hpp"
#include "user.hpp"
#include "file.hpp"
#include "config.h"
namespace phosphor
{
namespace user
{

// Update user password
void User::update(std::string newPassword)
{
    using namespace phosphor::logging;
    using UpdateFailure = sdbusplus::xyz::openbmc_project::
                               User::Password::Error::UpdateFailure;

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
            phosphor::logging::xyz::openbmc_project::User::
                Password::UpdateFailure::ERRNO(errno),
            phosphor::logging::xyz::openbmc_project::User::
                Password::UpdateFailure::REASON(
                    "Unable to read shadow password entry for user"));
    }

    // Done reading
    endspent();

    // 2: Parse and get crypt algo
    auto cryptAlgo = getCryptField(shdp.sp_pwdp);
    if (cryptAlgo.empty())
    {
        elog<UpdateFailure>(
            phosphor::logging::xyz::openbmc_project::User::
                Password::UpdateFailure::ERRNO(errno),
            phosphor::logging::xyz::openbmc_project::User::
                Password::UpdateFailure::REASON(
                    "Unable to read shadow password entry for user"));
    }

    // Update the new one
    phosphor::user::File file(fopen(SHADOW_FILE, "r+"));
    if ((file)() == NULL)
    {
        elog<UpdateFailure>(
            phosphor::logging::xyz::openbmc_project::User::
                Password::UpdateFailure::ERRNO(errno),
            phosphor::logging::xyz::openbmc_project::User::
                Password::UpdateFailure::REASON(
                    "Unable to open shadow password file"));
    }

    // Generate a random string from set [A-Za-z0-9./]
    std::string salt;
    salt.resize(std::atoi(SALT_LENGTH));
    std::generate_n(salt.begin(), salt.size(), randomChar);

    // Update shadow password pointer with hash
    auto saltString = getSaltString(cryptAlgo, salt);
    auto hash = generateHash(newPassword, saltString);
    shdp.sp_pwdp = const_cast<char*>(hash.c_str());

    // Apply
    r = putspent(&shdp, (file)());
    if (r < 0)
    {
        elog<UpdateFailure>(
            phosphor::logging::xyz::openbmc_project::User::
                Password::UpdateFailure::ERRNO(errno),
            phosphor::logging::xyz::openbmc_project::User::
                Password::UpdateFailure::REASON(
                    "Unable to update new password"));
    }
    return;
}

// Returns a random character in set [A-Za-z0-9./]
char User::randomChar()
{
    // Needed per crypt(3)
    std::string set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
                      "lmnopqrstuvwxyz0123456789./";
    return set.at(std::rand() % set.size());
}

// Extract crypto algorithm field
CryptAlgo User::getCryptField(char* spPwdp)
{
    return std::strtok(spPwdp, "$");
}

// Returns specific format of salt string
std::string User::getSaltString(const std::string& crypt,
                                const std::string& salt)
{
    return '$' + crypt + '$' + salt + '$';
}

// Given a password and salt, generates hash
std::string User::generateHash(const std::string& password,
                               const std::string& salt)
{
    return crypt(password.c_str(), salt.c_str());
}

} // namespace user
} // namespace phosphor
