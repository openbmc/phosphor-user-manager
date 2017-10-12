#include <sys/stat.h>
#include <string>
#include <fstream>
#include <experimental/filesystem>
#include <gtest/gtest.h>
#include <sdbusplus/bus.hpp>
#include "user.hpp"
namespace phosphor
{
namespace user
{

namespace fs = std::experimental::filesystem;

constexpr auto path = "/dummy/user";
constexpr auto testShadow = "/tmp/__tshadow__";
constexpr auto shadowCopy = "/tmp/__tshadowCopy__";
constexpr auto shadowCompare = "/tmp/__tshadowCompare__";

// New password
constexpr auto password = "passw0rd";

constexpr auto MD5 = "1";
constexpr auto SHA512 = "6";
constexpr auto salt = "1G.cK/YP";

// Example entry matching /etc/shadow structure
constexpr auto spPwdp = "$1$1G.cK/YP$JI5t0oliPxZveXOvLcZ/H.:17344:1:90:7:::";

class UserTest : public ::testing::Test
{
    public:
        const std::string md5Salt = '$' + std::string(MD5) + '$'
                                    + std::string(salt) + '$';
        const std::string shaSalt = '$' + std::string(SHA512) + '$'
                                    + std::string(salt) + '$';

        const std::string entry = fs::path(path).filename().string() +
                                  ':' + std::string(spPwdp);
        sdbusplus::bus::bus bus;
        phosphor::user::User user;

        // Gets called as part of each TEST_F construction
        UserTest()
            : bus(sdbusplus::bus::new_default()),
              user(bus, path)
        {
            // Create a shadow file entry
            std::ofstream file(testShadow);
            file << entry;
            file.close();

            // File to compare against
            std::ofstream compare(shadowCompare);
            compare << entry;
            compare.close();
        }

        // Gets called as part of each TEST_F destruction
        ~UserTest()
        {
            if (fs::exists(testShadow))
            {
                fs::remove(testShadow);
            }

            if (fs::exists(shadowCopy))
            {
                fs::remove(shadowCopy);
            }

            if (fs::exists(shadowCompare))
            {
                fs::remove(shadowCompare);
            }
        }

        /** @brief wrapper for get crypt field */
        auto getCryptField(char* data)
        {
            return User::getCryptField(
                            std::forward<decltype(data)>(data));
        }

        /** @brief wrapper for getSaltString */
        auto getSaltString(const std::string& crypt,
                           const std::string& salt)
        {
            return User::getSaltString(
                            std::forward<decltype(crypt)>(crypt),
                                std::forward<decltype(salt)>(salt));
        }

        /** @brief wrapper for generateHash */
        auto generateHash(const std::string& password,
                          const std::string& salt)
        {
            return User::generateHash(
                            std::forward<decltype(password)>(password),
                                std::forward<decltype(salt)>(salt));
        }

        /** @brief Applies the new password */
        auto applyPassword()
        {
            return user.applyPassword(testShadow, shadowCopy,
                                      password, salt);
        }
};

/** @brief Makes sure that SHA512 crypt field is extracted
 */
TEST_F(UserTest, sha512GetCryptField)
{
    auto salt = const_cast<char*>(shaSalt.c_str());
    EXPECT_EQ(SHA512, this->getCryptField(salt));
}

/** @brief Makes sure that MD5 crypt field is extracted as default
 */
TEST_F(UserTest, md55GetCryptFieldDefault)
{
    auto salt = const_cast<char*>("hello");
    EXPECT_EQ(MD5, this->getCryptField(salt));
}

/** @brief Makes sure that MD5 crypt field is extracted
 */
TEST_F(UserTest, md55GetCryptField)
{
    auto salt = const_cast<char*>(md5Salt.c_str());
    EXPECT_EQ(MD5, this->getCryptField(salt));
}

/** @brief Makes sure that salt string is put within $$
 */
TEST_F(UserTest, getSaltString)
{
    EXPECT_EQ(md5Salt, this->getSaltString(MD5, salt));
}

/** @brief Makes sure hash is generated correctly
 */
TEST_F(UserTest, generateHash)
{
    std::string sample = crypt(password, md5Salt.c_str());
    std::string actual = generateHash(password, md5Salt);
    EXPECT_EQ(sample, actual);
}

/** @brief Verifies that the correct password is written to file
 */
TEST_F(UserTest, applyPassword)
{
    // Update the password
    applyPassword();

    // Read files and compare
    std::ifstream shadow(testShadow);
    std::ifstream copy(shadowCompare);

    std::string shadowEntry;
    shadow >> shadowEntry;

    std::string shadowCompareEntry;
    copy >> shadowCompareEntry;

    EXPECT_EQ(shadowEntry, shadowCompareEntry);
}

/** @brief Verifies the shadow copy file is removed
 */
TEST_F(UserTest, checkShadowCopyRemove)
{
    // Update the password so that the temp file is in action
    applyPassword();

    // Compare the permission of 2 files
    struct stat shadow{};
    struct stat temp{};

    stat(testShadow, &shadow);
    stat(shadowCopy, &temp);
    EXPECT_EQ(false, fs::exists(shadowCopy));
}

/** @brief Verifies the permissions are correct
 */
TEST_F(UserTest, verifyShadowPermission)
{
    // Change the permission to 400-> -r--------
    chmod(testShadow, S_IRUSR);
    chmod(shadowCompare, S_IRUSR);

    // Update the password so that the temp file is in action
    applyPassword();

    // Compare the permission of 2 files.
    // file rename would make sure that the permissions
    // of old are moved to new
    struct stat shadow{};
    struct stat compare{};

    stat(testShadow, &shadow);
    stat(shadowCompare, &compare);
    EXPECT_EQ(shadow.st_mode, compare.st_mode);
}

} // namespace user
} // namespace phosphor
