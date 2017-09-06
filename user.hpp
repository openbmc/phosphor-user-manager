#pragma once

#include <string>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/User/Account/Password/server.hpp>
namespace phosphor
{
namespace user
{

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
              path(path)
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
};

} // namespace user
} // namespace phosphor
