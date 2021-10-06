#include "config.h"

#include "ldap_mapper_serialize.hpp"

#include <cereal/archives/binary.hpp>
#include <cereal/types/string.hpp>
#include <phosphor-logging/log.hpp>

#include <filesystem>
#include <fstream>

// Register class version
// From cereal documentation;
// "This macro should be placed at global scope"
CEREAL_CLASS_VERSION(phosphor::user::LDAPMapperEntry, CLASS_VERSION);

namespace phosphor
{
namespace user
{

using namespace phosphor::logging;

/** @brief Function required by Cereal to perform serialization.
 *
 *  @tparam Archive - Cereal archive type (binary in this case).
 *  @param[in] archive - reference to cereal archive.
 *  @param[in] entry- const reference to LDAP mapper entry
 *  @param[in] version - Class version that enables handling a serialized data
 *                       across code levels
 */
template <class Archive>
void save(Archive& archive, const LDAPMapperEntry& entry,
          const std::uint32_t version)
{
    archive(entry.groupName(), entry.privilege());
}

/** @brief Function required by Cereal to perform deserialization.
 *
 *  @tparam Archive - Cereal archive type (binary in our case).
 *  @param[in] archive - reference to cereal archive.
 *  @param[out] entry - LDAP mapper entry to be read
 *  @param[in] version - Class version that enables handling a serialized data
 *                       across code levels
 */
template <class Archive>
void load(Archive& archive, LDAPMapperEntry& entry, const std::uint32_t version)
{
    std::string groupName{};
    std::string privilege{};

    archive(groupName, privilege);

    entry.sdbusplus::xyz::openbmc_project::User::server::PrivilegeMapperEntry::
        groupName(groupName, true);
    entry.sdbusplus::xyz::openbmc_project::User::server::PrivilegeMapperEntry::
        privilege(privilege, true);
}

std::filesystem::path serialize(const LDAPMapperEntry& entry, Id id,
                                const std::filesystem::path& dir)
{
    auto path = dir / std::to_string(id);
    std::ofstream os(path.c_str(), std::ios::binary);
    cereal::BinaryOutputArchive oarchive(os);
    oarchive(entry);
    return path;
}

bool deserialize(const std::filesystem::path& path, LDAPMapperEntry& entry)
{
    try
    {
        if (std::filesystem::exists(path))
        {
            std::ifstream is(path.c_str(), std::ios::in | std::ios::binary);
            cereal::BinaryInputArchive iarchive(is);
            iarchive(entry);
            return true;
        }
        return false;
    }
    catch (const cereal::Exception& e)
    {
        log<level::ERR>(e.what());
        std::filesystem::remove(path);
        return false;
    }
    catch (const std::length_error& e)
    {
        log<level::ERR>(e.what());
        std::filesystem::remove(path);
        return false;
    }
}

} // namespace user
} // namespace phosphor
