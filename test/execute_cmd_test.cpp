#include "user_mgr.hpp"

#include <gtest/gtest.h>

TEST(ExecuteCmdTest, CommandReturnsEmptyOutput)
{
    std::vector<std::string> output = phosphor::user::executeCmd("/bin/true");
    ASSERT_TRUE(output.empty());
}

TEST(ExecuteCmdTest, CommandWithArgs)
{
    std::vector<std::string> output = phosphor::user::executeCmd(
        "/bin/echo", "testing", "with", "multiple", "args");
    ASSERT_EQ(output.size(), 1);
    EXPECT_EQ(output[0], "testing with multiple args");
}

TEST(ExecuteCmdTest, CommandReturnsOutput)
{
    std::vector<std::string> output =
        phosphor::user::executeCmd("/bin/echo", "-e", "\"hello\\nworld\"");
    ASSERT_EQ(output.size(), 2);
    EXPECT_EQ(output[0], "hello");
    EXPECT_EQ(output[1], "world");
}

TEST(ExecuteCmdTest, NonExistentCommand)
{
    EXPECT_THROW(
        phosphor::user::executeCmd("/path/to/nonexistent_command"),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
}

TEST(ExecuteCmdTest, CommandReturnsNonZeroExitCode)
{
    EXPECT_THROW(
        phosphor::user::executeCmd("/bin/false"),
        sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure);
}
