#pragma once

#include <stdio.h>
namespace phosphor
{
namespace user
{
/** @class File
 *  @brief Responsible for handling file pointer.
 *  Needed by putspent(3)
 */
class File
{
    private:
        /** @brief handler for operating on file */
        FILE *fp = NULL;

    public:
        File() = delete;
        File(const File&) = delete;
        File& operator=(const File&) = delete;
        File(File&&) = delete;
        File& operator=(File&&) = delete;

        /** @brief Saves File pointer and uses it to do file operation
         *
         *  @param[in] fp - File pointer
         */
        File(FILE *fp) : fp(fp)
        {
            // Nothing
        }

        ~File()
        {
            if (fp)
            {
                fclose(fp);
            }
        }

        auto operator()()
        {
            return fp;
        }
};

} // namespace user
} // namespace phosphor
