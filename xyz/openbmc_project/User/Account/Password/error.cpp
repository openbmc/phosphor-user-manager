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
namespace Password
{
namespace Error
{
const char* UpdateFailure::name() const noexcept
{
    return errName;
}
const char* UpdateFailure::description() const noexcept
{
    return errDesc;
}
const char* UpdateFailure::what() const noexcept
{
    return errWhat;
}
const char* InvalidPassword::name() const noexcept
{
    return errName;
}
const char* InvalidPassword::description() const noexcept
{
    return errDesc;
}
const char* InvalidPassword::what() const noexcept
{
    return errWhat;
}

} // namespace Error
} // namespace Password
} // namespace Account
} // namespace User
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus

