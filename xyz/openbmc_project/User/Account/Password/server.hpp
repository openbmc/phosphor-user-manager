#pragma once
#include <tuple>
#include <systemd/sd-bus.h>
#include <sdbusplus/server.hpp>

namespace sdbusplus
{
namespace xyz
{
namespace openbmc_project
{
namespace User
{
namespace Account
{
namespace server
{

class Password
{
    public:
        /* Define all of the basic class operations:
         *     Not allowed:
         *         - Default constructor to avoid nullptrs.
         *         - Copy operations due to internal unique_ptr.
         *         - Move operations due to 'this' being registered as the
         *           'context' with sdbus.
         *     Allowed:
         *         - Destructor.
         */
        Password() = delete;
        Password(const Password&) = delete;
        Password& operator=(const Password&) = delete;
        Password(Password&&) = delete;
        Password& operator=(Password&&) = delete;
        virtual ~Password() = default;

        /** @brief Constructor to put object onto bus at a dbus path.
         *  @param[in] bus - Bus to attach to.
         *  @param[in] path - Path to attach at.
         */
        Password(bus::bus& bus, const char* path);



        /** @brief Implementation for Update
         *  Update the user password
         *
         *  @param[in] oldPassword - old password string
         *  @param[in] newPassword - new password string
         */
        virtual void update(
            std::string oldPassword,
            std::string newPassword) = 0;




    private:

        /** @brief sd-bus callback for Update
         */
        static int _callback_Update(
            sd_bus_message*, void*, sd_bus_error*);


        static constexpr auto _interface = "xyz.openbmc_project.User.Account.Password";
        static const vtable::vtable_t _vtable[];
        sdbusplus::server::interface::interface
                _xyz_openbmc_project_User_Account_Password_interface;


};


} // namespace server
} // namespace Account
} // namespace User
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus

