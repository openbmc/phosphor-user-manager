#include <algorithm>
#include <sdbusplus/server.hpp>
#include <sdbusplus/exception.hpp>
#include <xyz/openbmc_project/User/Account/Password/server.hpp>

#include <xyz/openbmc_project/User/Account/Password/error.hpp>
#include <xyz/openbmc_project/User/Account/Password/error.hpp>

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

Password::Password(bus::bus& bus, const char* path)
        : _xyz_openbmc_project_User_Account_Password_interface(
                bus, path, _interface, _vtable, this)
{
}


int Password::_callback_Update(
        sd_bus_message* msg, void* context, sd_bus_error* error)
{
    using sdbusplus::server::binding::details::convertForMessage;

    try
    {
        auto m = message::message(msg);
#if 1
        {
            auto tbus = m.get_bus();
            sdbusplus::server::transaction::Transaction t(tbus, m);
            sdbusplus::server::transaction::set_id
                (std::hash<sdbusplus::server::transaction::Transaction>{}(t));
        }
#endif

        std::string oldPassword{};
    std::string newPassword{};

        m.read(oldPassword, newPassword);

        auto o = static_cast<Password*>(context);
        o->update(oldPassword, newPassword);

        auto reply = m.new_method_return();
        // No data to append on reply.

        reply.method_return();
    }
    catch(sdbusplus::internal_exception_t& e)
    {
        sd_bus_error_set_const(error, e.name(), e.description());
        return -EINVAL;
    }
    catch(sdbusplus::xyz::openbmc_project::User::Account::Password::Error::UpdateFailure& e)
    {
        sd_bus_error_set_const(error, e.name(), e.description());
        return -EINVAL;
    }
    catch(sdbusplus::xyz::openbmc_project::User::Account::Password::Error::InvalidPassword& e)
    {
        sd_bus_error_set_const(error, e.name(), e.description());
        return -EINVAL;
    }

    return true;
}

namespace details
{
namespace Password
{
static const auto _param_Update =
        utility::tuple_to_array(message::types::type_id<
                std::string, std::string>());
static const auto _return_Update =
        utility::tuple_to_array(std::make_tuple('\0'));
}
}




const vtable::vtable_t Password::_vtable[] = {
    vtable::start(),

    vtable::method("Update",
                   details::Password::_param_Update
                        .data(),
                   details::Password::_return_Update
                        .data(),
                   _callback_Update),
    vtable::end()
};

} // namespace server
} // namespace Account
} // namespace User
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus

