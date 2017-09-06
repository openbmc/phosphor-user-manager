#pragma once

#include <sdbusplus/exception.hpp>

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

struct UpdateFailure final : public sdbusplus::exception_t
{
    static constexpr auto errName = "xyz.openbmc_project.User.Account.Password.Error.UpdateFailure";
    static constexpr auto errDesc =
            "Password update failed";
    static constexpr auto errWhat =
            "xyz.openbmc_project.User.Account.Password.Error.UpdateFailure: Password update failed";

    const char* name() const noexcept override;
    const char* description() const noexcept override;
    const char* what() const noexcept override;
};

struct InvalidPassword final : public sdbusplus::exception_t
{
    static constexpr auto errName = "xyz.openbmc_project.User.Account.Password.Error.InvalidPassword";
    static constexpr auto errDesc =
            "Password is invalid";
    static constexpr auto errWhat =
            "xyz.openbmc_project.User.Account.Password.Error.InvalidPassword: Password is invalid";

    const char* name() const noexcept override;
    const char* description() const noexcept override;
    const char* what() const noexcept override;
};

} // namespace Error
} // namespace Password
} // namespace Account
} // namespace User
} // namespace openbmc_project
} // namespace xyz
} // namespace sdbusplus

