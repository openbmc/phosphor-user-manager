#include <iostream>
#include <sys/types.h>
#include <chrono>
#include <string>
#include <linux/input.h>
#include <gtest/gtest.h>
#include <sdbusplus/bus.hpp>
#include "user.hpp"

namespace phosphor
{
namespace user
{

constexpr auto dummyPath = "/dummy/path";

class UserTest : public ::testing::Test
{
    public:
        std::string salt = "1G.cK/YP";
        std::string MD5 = "1";
        std::string md5Salt = '$' + MD5 + '$' + salt + '$';
        std::string SHA512 = "6";
        std::string shaSalt = '$' + SHA512 + '$' + salt + '$';

        std::string password = "0penBmc";
        std::string spPwdp = "$1$1G.cK/YP$TU3uIWLFx4OD0XQNpj667:17344:1:90:7:::";

        sdbusplus::bus::bus bus;
        phosphor::user::User user;

        // Gets called as part of each TEST_F construction
        UserTest()
            : bus(sdbusplus::bus::new_default()),
              user(bus, dummyPath)
        {
            // Do nothing
        }

        // Gets called as part of each TEST_F destruction
        ~UserTest()
        {
            // Nothing to do
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
    std::string sample = crypt(password.c_str(), md5Salt.c_str());
    std::string actual = generateHash(password, md5Salt);
    EXPECT_EQ(sample, actual);
}

/** @brief Validate hashPassword
 */
TEST_F(UserTest, hashPassword)
{
    std::string sample = crypt(password.c_str(), md5Salt.c_str());
    std::string actual = this->user.hashPassword(
                            const_cast<char*>(
                                        spPwdp.c_str()),
                                        password,
                                        salt);
    EXPECT_EQ(sample, actual);
}

} // namespace user
} // namespace phosphor
