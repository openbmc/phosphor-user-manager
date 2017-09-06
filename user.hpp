#pragma once

#include <cstring>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/User/Password/server.hpp>
namespace phosphor
{
namespace user
{

using CryptAlgo = std::string;

namespace Base = sdbusplus::xyz::openbmc_project::User::server;
using Interface = sdbusplus::server::object::object<Base::Password>;

/** @class User
 *  @brief Responsible for managing a specific user account.
 *         It is implementing just the Password interface
 *         for now.
 */
class User : public Interface
{
    public:
        User() = delete;
        ~User() = default;
        User(const User&) = delete;
        User& operator=(const User&) = delete;
        User(User&&) = delete;
        User& operator=(User&&) = delete;

        /** @brief Constructs User object.
         *
         *  @param[in] bus  - sdbusplus handler
         *  @param[in] path - D-Bus path
         */
        User(sdbusplus::bus::bus& bus, const char* path)
            : Interface(bus, path),
              bus(bus),
              path(path),
              user(std::move(std::strrchr(path, '/') + 1))
        {
            // Do nothing
        }

        /** @brief user password update method. Since needs an already
         *         authenticated session, old password is not needed.
         *
         *  @param[in] newPassword - New password
         */
        void update(std::string newPassword) override;

    private:
        /** @brief sdbusplus handler */
        sdbusplus::bus::bus& bus;

        /** @brief object path */
        const std::string& path;

        /** @brief User id extracted from object path */
        const std::string user;

        /** @brief Extracts crypto number from the shadow entry for user
         *
         *  @param[in] spPwdp - sp_pwdp of struct spwd
         */
        static CryptAlgo getCryptField(char* spPwdp);

        /** @brief Generates one-way hash based on salt and password
         *
         *  @param[in] password - clear text password
         *  @param[in] salt     - Combination of crypto method and salt
         *                        Eg: $1$HELLO$, where in 1 is crypto method
         *                        and HELLO is salt
         */
        static std::string generateHash(const std::string& password,
                                        const std::string& salt);

        /** @brief returns salt string with $ delimiter.
         *         Eg: If crypt is 1 and salt is HELLO, returns $1$HELLO$
         *
         *  @param[in] crypt - Crypt number in string
         *  @param[in] salt  - salt
         */
        static std::string getSaltString(const std::string& crypt,
                                         const std::string& salt);
};

} // namespace user
} // namespace phosphor
