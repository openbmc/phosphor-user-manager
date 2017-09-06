#pragma once

#include <string>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/User/Password/server.hpp>
namespace phosphor
{
namespace user
{

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
              path(path)
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
};

} // namespace user
} // namespace phosphor
