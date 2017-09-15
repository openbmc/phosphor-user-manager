#pragma once

#include <cstring>
#include <experimental/filesystem>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/User/Password/server.hpp>
namespace phosphor
{
namespace user
{

using CryptAlgo = std::string;

namespace fs = std::experimental::filesystem;
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
              user(fs::path(path).filename())
        {
            // Do nothing
        }

        /** @brief user password set method. If this is called for
         *         a user ID that already has the password, the password
         *         would be updated, else password would be created.
         *         Since this needs an already authenticated session,
         *         old password is not needed.
         *
         *  @param[in] newPassword - New password
         */
        void setPassword(std::string newPassword) override;


    private:
        /** @brief sdbusplus handler */
        sdbusplus::bus::bus& bus;

        /** @brief object path */
        const std::string& path;

        /** @brief User id extracted from object path */
        const std::string user;

        /** @brief Returns a random string from set [A-Za-z0-9./]
         *         of length size
         *
         *  @param[in] numChars - length of string
         */
        static const std::string randomString(int length);

        /** @brief Rerturns password hash created with crypt algo,
         *         salt and password
         *
         *  @param[in] spPwdp   - sp_pwdp of struct spwd
         *  @param[in] password - clear text password
         *  @param[in] salt     - Random salt
         */
        std::string hashPassword(char* spPwdp,
                                 const std::string& password,
                                 const std::string& salt);

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

        /** @brief Applies the password for a given user.
         *         Writes shadow entries into a temp file
         *
         *  @param[in] shadowFile - shadow password file
         *  @param[in] tempFile   - Temporary file
         *  @param[in] password   - clear text password
         *  @param[in] salt       - salt
         */
        void applyPassword(const std::string& shadowFile,
                           const std::string& tempFile,
                           const std::string& password,
                           const std::string& salt);

        /** @brief For enabling test cases */
        friend class UserTest;
};

} // namespace user
} // namespace phosphor
