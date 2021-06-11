//
// Sophos - Forward Private Searchable Encryption
// Copyright (C) 2016 Raphael Bost
//
// This file is part of Sophos.
//
// Sophos is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// Sophos is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with Sophos.  If not, see <http://www.gnu.org/licenses/>.
//


#include <sse/schemes/utils/utils.hpp>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fts.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>
namespace sse {
namespace utility {

bool is_file(const std::string& path)
{
    struct stat sb;

    return (stat(path.c_str(), &sb) == 0 && S_ISREG(sb.st_mode));
}

bool is_directory(const std::string& path)
{
    struct stat sb;

    return (stat(path.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode));
}

bool exists(const std::string& path)
{
    struct stat sb;

    return (stat(path.c_str(), &sb) == 0);
}

bool create_directory(const std::string& path, mode_t mode)
{
    return mkdir(path.data(), mode) == 0;
}

// the implementation of this function was inspired from
// https://stackoverflow.com/a/27808574
bool remove_directory(const std::string& path)
{
    if (!exists(path)) {
        return true;
    }

    const char* dir = path.c_str();


    // Cast needed (in C) because fts_open() takes a "char * const *",
    // instead of a "const char * const *", which is only allowed in C++.
    // fts_open() does not modify the argument.
    // char* files[] = {const_cast<char*>(dir), nullptr};
    std::array<char*, 2> files = {const_cast<char*>(dir), nullptr};

    // FTS_NOCHDIR  - Avoid changing cwd, which could cause unexpected
    // behavior
    //                in multithreaded programs
    // FTS_PHYSICAL - Don't follow symlinks. Prevents deletion of files
    // outside
    //                of the specified directory
    // FTS_XDEV     - Don't cross filesystem boundaries
    FTS* ftsp = fts_open(
        files.data(), FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, nullptr);
    if (ftsp == nullptr) {
        std::string message = "When deleting directory " + path;
        message += ": fts_open failed: ";
        message += strerror(errno);
        throw std::runtime_error(message);
    }

    FTSENT* curr;

    while ((curr = fts_read(ftsp)) != nullptr) {
        switch (curr->fts_info) {
        case FTS_NS:
        case FTS_DNR:
        case FTS_ERR: {
            std::string message = "When deleting directory " + path;
            message += ": ";
            message += curr->fts_accpath;
            message += "fts_read error: ";
            message += strerror(curr->fts_errno);

            // gracefully close the fts before throwing
            fts_close(ftsp);

            throw std::runtime_error(message);
        }
        case FTS_DC:
        case FTS_DOT:
        case FTS_NSOK:
            // Not reached unless FTS_LOGICAL, FTS_SEEDOT, or FTS_NOSTAT
            // were passed to fts_open()
            // break;

        case FTS_D:
            // Do nothing. Need depth-first search, so directories are
            // deleted in FTS_DP
            break;

        case FTS_DP:
        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
        case FTS_DEFAULT: {
            if (remove(curr->fts_accpath) < 0) {
                std::string message = "When deleting directory " + path;
                message += ": ";
                message += curr->fts_accpath;
                message += "Failed to remove: ";
                message += strerror(errno);

                // gracefully close the fts before throwing
                fts_close(ftsp);

                throw std::runtime_error(message);
            }
            break;
        }
        }
    }

    fts_close(ftsp);

    return true;
}


bool remove_file(const std::string& path)
{
    return unlink(path.c_str()) == 0;
}

int open_fd(const std::string& filename, bool direct_io)
{
    int flags = (O_CREAT | O_RDWR);

    if (direct_io) {
#if !defined(__APPLE__)
        flags |= O_DIRECT;
#endif
    }

    int fd = open(filename.c_str(), flags, 0644);

    if (fd == -1) {
        throw std::runtime_error("Error when opening file " + filename
                                 + "; errno " + std::to_string(errno) + "("
                                 + strerror(errno) + ")");
    }

    if (direct_io) {
#ifdef __APPLE__
        if (fcntl(fd, F_NOCACHE, 1) == -1) {
            close(fd);
            throw std::runtime_error(
                "Error calling fcntl F_NOCACHE on file " + filename + "; errno "
                + std::to_string(errno) + "(" + strerror(errno) + ")");
        }
#endif
    }

    return fd;
}

ssize_t file_size(int fd)
{
    struct stat s;
    if (fstat(fd, &s) == -1) {
        int saveErrno = errno;
        throw std::runtime_error("Error when get size of file descriptor "
                                 + std::to_string(fd) + "; errno "
                                 + std::to_string(saveErrno) + "("
                                 + strerror(saveErrno) + ")");
    }
    return (s.st_size);
}

std::string hex_string(const std::string& in)
{
    std::ostringstream out;
    for (unsigned char c : in) {
        out << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<uint>(c);
    }
    return out.str();
}

std::ostream& print_hex(std::ostream& out, const std::string& s)
{
    for (unsigned char c : s) {
        out << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<uint>(c);
    }

    return out;
}

std::string hex_string(const uint64_t& a)
{
    std::ostringstream out;
    out << std::hex << std::setw(16) << std::setfill('0') << a;
    return out.str();
}

std::string hex_string(const uint32_t& a)
{
    std::ostringstream out;
    out << std::hex << std::setw(8) << std::setfill('0') << a;
    return out.str();
}

void append_keyword_map(std::ostream&      out,
                        const std::string& kw,
                        uint32_t           index)
{
    out << kw << "       " << std::hex << index << "\n";
}


size_t os_page_size()
{
    return sysconf(_SC_PAGE_SIZE);
}

size_t device_page_size(int fd)
{
    struct statvfs stats;


    fstatvfs(fd, &stats);
#if __APPLE__
    return stats.f_frsize;
#else
    return stats.f_bsize;
#endif
}

size_t device_page_size(const std::string& path)
{
    if (!exists(path)) {
        return 0;
    }
    struct statvfs stats;


    statvfs(path.c_str(), &stats);


    return stats.f_bsize;
}

} // namespace utility
} // namespace sse