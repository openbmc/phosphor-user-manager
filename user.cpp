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
#include "user.hpp"
namespace phosphor
{
namespace user
{

// Update user password
void User::update(std::string newPassword)
{
    // Needed by getspnam_r
    struct spwd shdp;
    struct spwd* pshdp;

    // This should be fine even if SHA512 is used.
    std::array<char,1024> buffer{};

    // 1: Read /etc/shadow for the user
    auto r = getspnam_r(user.c_str(), &shdp, buffer.data(),
                        buffer.max_size(), &pshdp);
    if (r < 0)
    {
        return;
        // TODO: Throw an error
    }

    // Done reading
    endspent();

    // 2: Parse and get crypt algo
    auto cryptAlgo = getCryptField(shdp.sp_pwdp);
    if (cryptAlgo.empty())
    {
        // TODO: Throw error getting crypt field
    }

    // TODO: Update the password in next commit
    return;
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
