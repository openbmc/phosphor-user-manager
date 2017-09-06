#pragma once

#include <cstring>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/User/Account/Password/server.hpp>
namespace phosphor
{
namespace user
{

using CryptAlgo = std::string;
using Salt = std::string;
using Hash = std::string;
using shadowFields = std::tuple<CryptAlgo, Salt, Hash>;

namespace Base = sdbusplus::xyz::openbmc_project::User::Account::server;
using Interface = sdbusplus::server::object::object<Base::Password>;

/** @class Account
 *  @brief Responsible for managing a specific user account.
 *         It is implementing just the Password interface
 *         for now.
 */
class Account : public Interface
{
    public:
        Account() = delete;
        ~Account() = default;
        Account(const Account&) = delete;
        Account& operator=(const Account&) = delete;
        Account(Account&&) = delete;
        Account& operator=(Account&&) = delete;

        /** @brief Constructs Account object.
         *
         *  @param[in] bus  - sdbusplus handler
         *  @param[in] path - D-Bus path
         */
        Account(sdbusplus::bus::bus& bus, const char* path)
            : Interface(bus, path),
              bus(bus),
              path(path),
              user(std::strrchr(path, '/') + 1)
        {
            // Do nothing
        }

        /** @brief user password update method
         *
         *  @param[in] oldPassword - Old password
         *  @param[in] newPassword - New password
         */
        void update(std::string oldPassword,
                    std::string newPassword) override;

    private:
        /** @brief sdbusplus handler */
        sdbusplus::bus::bus& bus;

        /** @brief object path */
        const std::string& path;

        /** @brief User id extracted from object path */
        const std::string user;

        /** @brief Returns a random character from set [A-Za-z0-9./] */
        static char randomChar();

        /** @brief Extracts crypto number, salt and hash from input
         *         and returns it as tuple
         *
         *  @param[in] spPwdp - sp_pwdp of struct spwd
         */
        static shadowFields getShadowFields(char* spPwdp);

        /** @brief Generates one-way hash based on salt and password
         *
         *  @param[in] password - clear text password
         *  @param[in] salt     - Combination of crypto method and salt
         *                        Eg: $1$HELLO$, where in 1 is crypto method
         *                        and HELLO is salt
         */
        static std::string generateHash(const std::string& password,
                                        const std::string& salt);

        /** @brief returns salt string with $ delimiter
         *
         *  @param[in] crypt - Crypt number in string
         *  @param[in] salt  - salt
         */
        static std::string getSaltString(const std::string& crypt,
                                         const std::string& salt);

        /** @brief Validates if the given password matches
         *         with entry in shadow
         *
         *  @param[in] password - clear text password
         *  @param[in] entry    - Tuple of [crypto number, salt, hash]
         *                        extracted from /etc/shadow for the user
         *
         *  @return - True on match, False if not
         */
         bool validatePassword(const std::string& password,
                               const shadowFields& entry);
};

} // namespace user
} // namespace phosphor
