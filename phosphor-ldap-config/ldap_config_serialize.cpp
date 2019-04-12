#include <cereal/types/string.hpp>
#include <cereal/types/vector.hpp>
#include <cereal/archives/binary.hpp>
#include <fstream>

#include "ldap_config_serialize.hpp"
#include "ldap_config.hpp"
#include <phosphor-logging/log.hpp>
#include "config.h"

// Register class version
// From cereal documentation;
// "This macro should be placed at global scope"
CEREAL_CLASS_VERSION(phosphor::ldap::Config, CLASS_VERSION);

namespace phosphor
{
namespace ldap
{

using namespace phosphor::logging;

/** @brief Function required by Cereal to perform serialization.
 *  @tparam Archive - Cereal archive type (binary in our case).
 *  @param[in] archive - reference to Cereal archive.
 *  @param[in] config - const reference to ldap config.
 *  @param[in] version - Class version that enables handling
 *                       a serialized data across code levels
 */
template <class Archive>
void save(Archive& archive, const Config& config, const std::uint32_t version)
{
    archive(config.enabled());
    archive(config.lDAPServerURI());
    archive(config.lDAPBindDN());
    archive(config.lDAPBaseDN());
    archive(config.lDAPSearchScope());
    archive(config.lDAPBindPassword);
    archive(config.userNameAttribute());
    archive(config.groupNameAttribute());
    archive(config.tlsCacertFile);
}

/** @brief Function required by Cereal to perform deserialization.
 *  @tparam Archive - Cereal archive type (binary in our case).
 *  @param[in] archive - reference to Cereal archive.
 *  @param[in] config -  reference of ldap config object.
 *  @param[in] version - Class version that enables handling
 *                       a serialized data across code levels
 */
template <class Archive>
void load(Archive& archive, Config& config, const std::uint32_t version)
{
    bool bVal;
    archive(bVal);
    config.EnableIface::enabled(bVal);

    std::string str;
    archive(str);
    config.ConfigIface::lDAPServerURI(str);

    archive(str);
    config.ConfigIface::lDAPBindDN(str);

    archive(str);
    config.ConfigIface::lDAPBaseDN(str);

    ConfigIface::SearchScope scope;
    archive(scope);
    config.ConfigIface::lDAPSearchScope(scope);

    archive(str);
    config.lDAPBindPassword = str;

    archive(str);
    config.ConfigIface::userNameAttribute(str);

    archive(str);
    config.ConfigIface::groupNameAttribute(str);

    archive(str);
    config.tlsCacertFile = str;
}

fs::path serialize(const Config& config, const fs::path& path)
{
    std::ofstream os(path.string(), std::ios::binary | std::ios::out);
    cereal::BinaryOutputArchive oarchive(os);
    oarchive(config);
    return path;
}

bool deserialize(const fs::path& path, Config& config)
{
    try
    {
        if (fs::exists(path))
        {
            std::ifstream is(path.c_str(), std::ios::in | std::ios::binary);
            cereal::BinaryInputArchive iarchive(is);
            iarchive(config);
            return true;
        }
        return false;
    }
    catch (cereal::Exception& e)
    {
        log<level::ERR>(e.what());
        std::error_code ec;
        fs::remove(path, ec);
        return false;
    }
    catch (const fs::filesystem_error& e)
    {
        return false;
    }
}

} // namespace ldap
} // namespace phosphor
