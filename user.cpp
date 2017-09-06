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
#include <random>
#include <errno.h>
#include <xyz/openbmc_project/Common/error.hpp>
#include <phosphor-logging/log.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include "user.hpp"
#include "file.hpp"
#include "shadowlock.hpp"
#include "config.h"
namespace phosphor
{
namespace user
{

constexpr auto SHADOW_FILE = "/etc/shadow";

// See crypt(3)
constexpr int SALT_LENGTH = 16;

using namespace phosphor::logging;
using InsufficientPermission = sdbusplus::xyz::openbmc_project::Common::
                                    Error::InsufficientPermission;
using InternalFailure = sdbusplus::xyz::openbmc_project::Common::
                                    Error::InternalFailure;
// Sets or updates the password
void User::setPassword(std::string newPassword)
{
    // Gate any access to /etc/shadow
    phosphor::user::shadow::Lock lock();

    // rewind to the start of shadow entry
    setspent();

    // Generate a random string from set [A-Za-z0-9./]
    std::string salt{};
    salt.resize(SALT_LENGTH);
    salt = randomString(SALT_LENGTH);

    auto tempShadowFile = std::string("/etc/__") +
                          randomString(SALT_LENGTH) +
                          std::string("__");

    // Apply the change. Updates could be directly made to shadow
    // but then any update must be contained within the boundary
    // of that user, else it would run into next entry and thus
    // corrupting it. Classic example is when a password is set on
    // a user ID that does not have a prior password
    applyPassword(SHADOW_FILE, tempShadowFile,
                  newPassword, salt);

    // Done
    endspent();

    // Everything must be fine at this point
    fs::rename(tempShadowFile, SHADOW_FILE);
    return;
}

void User::applyPassword(const std::string& shadowFile,
                         const std::string& tempFile,
                         const std::string& password,
                         const std::string& salt)
{
    // Needed by getspnam_r
    struct spwd shdp;
    struct spwd* pshdp;

    // This should be fine even if SHA512 is used.
    std::array<char,1024> buffer{};

    // Open the shadow file for reading
    phosphor::user::File shadow(fopen(shadowFile.c_str(), "r"));
    if ((shadow)() == NULL)
    {
        if (errno == EACCES)
        {
            log<level::ERR>("Access denied opening shadow file");
            elog<InsufficientPermission>();
        }
        else
        {
            log<level::ERR>("Error opening shadow file",
                    entry("USER=%s",user.c_str()),
                        entry("ERRNO=%d", errno));
            elog<InternalFailure>();
        }
    }

    // Open the temp shadow file for writing
    phosphor::user::File temp(fopen(tempFile.c_str(), "w"));
    if ((temp)() == NULL)
    {
        log<level::ERR>("Error opening temp shadow file",
                entry("USER=%s",user.c_str()),
                    entry("ERRNO=%d", errno));
        elog<InternalFailure>();
    }

    // Read shadow file and process
    while (true)
    {
        auto r = fgetspent_r((shadow)(), &shdp, buffer.data(),
                             buffer.max_size(), &pshdp);
        if (r)
        {
            if (errno == EACCES)
            {
                log<level::ERR>("Access denied reading shadow file");
                elog<InsufficientPermission>();
            }
            else
            {
                // Seem to have run over all
                break;
            }
        }

        // Hash of password if the user matches
        std::string hash{};

        // Matched user
        if (user == shdp.sp_namp)
        {
            // Update with new hashed password
            hash = hashPassword(shdp.sp_pwdp, password, salt);
            shdp.sp_pwdp = const_cast<char*>(hash.c_str());
        }

        // Apply
        r = putspent(&shdp, (temp)());
        if (r < 0)
        {
            if (errno == EACCES)
            {
                log<level::ERR>("Access denied updating temp shadow file");
                elog<InsufficientPermission>();
            }
            else
            {
                log<level::ERR>("Error updating temp shadow file",
                        entry("USER=%s",user.c_str()),
                        entry("ERRNO=%d", errno));
                elog<InternalFailure>();
            }
        }
    } // All entries
    return;
}

std::string User::hashPassword(char* spPwdp,
                               const std::string& password,
                               const std::string& salt)
{
    // Parse and get crypt algo
    auto cryptAlgo = getCryptField(spPwdp);
    if (cryptAlgo.empty())
    {
        log<level::ERR>("Error finding crypt algo",
                entry("USER=%s",user.c_str()),
                    entry("ERRNO=%d", errno));
        elog<InternalFailure>();
    }

    // Update shadow password pointer with hash
    auto saltString = getSaltString(cryptAlgo, salt);
    return generateHash(password, saltString);
}

// Returns a random string in set [A-Za-z0-9./]
// of size numChars
const std::string User::randomString(int length)
{
    // Populated random string
    std::string random{};

    // Needed per crypt(3)
    std::string set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"
                      "lmnopqrstuvwxyz0123456789./";

    // Will be used to obtain a seed for the random number engine
    std::random_device rd;

    // Standard mersenne_twister_engine seeded with rd()
    std::mt19937 gen(rd());

    std::uniform_int_distribution<> dis(0, set.size()-1);
    for (int count = 0; count < length; count++)
    {
        // Use dis to transform the random unsigned int generated by
        // gen into a int in [1, SALT_LENGTH]
        random.push_back(set.at(dis(gen)));
    }
    return random;
}

// Extract crypto algorithm field
CryptAlgo User::getCryptField(char* spPwdp)
{
    char* savePtr{};
    if (std::string{spPwdp}.front() != '$')
    {
        return DEFAULT_CRYPT_ALGO;
    }
    return strtok_r(spPwdp, "$", &savePtr);
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
