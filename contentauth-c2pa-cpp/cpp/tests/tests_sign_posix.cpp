// Copyright 2026 Adobe. All rights reserved.
// Licensed under the Apache License, Version 2.0 or the MIT license, at your option.

#include "signing_support.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

using namespace c2pa::sm;
using namespace support;

namespace {

struct Faults;
thread_local Faults *active_faults = nullptr;

struct Faults {
    enum class Stat { Normal, Error, NegativeSize, NotRegular };
    int read_interrupts = 0, write_interrupts = 0;
    int read_error = 0, write_error = 0, sync_error = 0;
    int reads = 0, writes = 0, stats = 0, syncs = 0;
    size_t chunk = std::numeric_limits<size_t>::max();
    Stat stat = Stat::Normal;

    Faults() : previous_(std::exchange(active_faults, this)) {}
    ~Faults() { active_faults = previous_; }
    Faults(const Faults &) = delete;
    Faults &operator=(const Faults &) = delete;

private:
    Faults *previous_;
};

struct TemporaryDirectory {
    std::filesystem::path path;
    TemporaryDirectory() {
        auto pattern = (std::filesystem::temp_directory_path() / "c2pa-sm-posix-XXXXXX").string();
        const auto *created = ::mkdtemp(pattern.data());
        if (!created) throw std::runtime_error("cannot create POSIX test directory");
        path = created;
    }
    ~TemporaryDirectory() {
        std::error_code error;
        std::filesystem::remove_all(path, error);
        EXPECT_FALSE(error) << error.message();
    }
};

}  // namespace

// GNU linker wrapping affects only this executable; other threads and calls
// outside a Faults scope retain the real system-call behavior.
extern "C" {
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __real_pwrite(int, const void *, size_t, off_t);
int __real_fstat(int, struct stat *);
int __real_fsync(int);

ssize_t __wrap_pread(int fd, void *buffer, size_t count, off_t offset) {
    if (auto *faults = active_faults) {
        ++faults->reads;
        if (faults->read_interrupts > 0) {
            --faults->read_interrupts;
            errno = EINTR;
            return -1;
        }
        if (faults->read_error) {
            errno = faults->read_error;
            return -1;
        }
        count = std::min(count, faults->chunk);
    }
    return __real_pread(fd, buffer, count, offset);
}

ssize_t __wrap_pwrite(int fd, const void *buffer, size_t count, off_t offset) {
    if (auto *faults = active_faults) {
        ++faults->writes;
        if (faults->write_interrupts > 0) {
            --faults->write_interrupts;
            errno = EINTR;
            return -1;
        }
        if (faults->write_error) {
            errno = faults->write_error;
            return -1;
        }
        count = std::min(count, faults->chunk);
    }
    return __real_pwrite(fd, buffer, count, offset);
}

int __wrap_fstat(int fd, struct stat *info) {
    if (auto *faults = active_faults) {
        ++faults->stats;
        if (faults->stat == Faults::Stat::Error) {
            errno = EIO;
            return -1;
        }
        const auto result = __real_fstat(fd, info);
        if (result == 0) {
            if (faults->stat == Faults::Stat::NegativeSize) info->st_size = -1;
            if (faults->stat == Faults::Stat::NotRegular) info->st_mode = S_IFDIR;
        }
        return result;
    }
    return __real_fstat(fd, info);
}

int __wrap_fsync(int fd) {
    if (auto *faults = active_faults) {
        ++faults->syncs;
        if (faults->sync_error) {
            errno = faults->sync_error;
            return -1;
        }
    }
    return __real_fsync(fd);
}
}

TEST(PosixSigning, interrupted_reads_and_writes_retry_without_losing_bytes) {
    TemporaryDirectory directory;
    FileBuildHost host(C2PA_SM_FIXTURE, directory.path / "out.jpg");
    const std::vector<uint8_t> expected{0xff, 0xd8, 0xff};
    Faults faults;
    faults.read_interrupts = 2;
    faults.write_interrupts = 2;
    EXPECT_EQ(read_build_host(host, BuildStream::Source, 0, expected.size()), expected);
    EXPECT_EQ(faults.reads, 3);
    host.write(BuildStream::Output, 0, expected);
    EXPECT_EQ(faults.writes, 3);
    EXPECT_EQ(read_build_host(host, BuildStream::Output, 0, expected.size()), expected);
}

TEST(PosixSigning, partial_reads_and_writes_advance_the_buffer_and_file_offset) {
    TemporaryDirectory directory;
    FileBuildHost host(C2PA_SM_FIXTURE, directory.path / "out.jpg");
    const std::vector<uint8_t> expected{0xff, 0xd8, 0xff};
    Faults faults;
    faults.chunk = 1;
    EXPECT_EQ(read_build_host(host, BuildStream::Source, 0, expected.size()), expected);
    EXPECT_EQ(faults.reads, 3);
    host.write(BuildStream::Output, 0, expected);
    EXPECT_EQ(faults.writes, 3);
    EXPECT_EQ(read_build_host(host, BuildStream::Output, 0, expected.size()), expected);
    EXPECT_EQ(faults.reads, 6);
}

TEST(PosixSigning, non_interrupt_io_errors_are_reported_without_retrying) {
    TemporaryDirectory directory;
    FileBuildHost host(C2PA_SM_FIXTURE, directory.path / "out.jpg");
    {
        Faults faults;
        faults.read_error = EIO;
        const auto reply = read_build_reply(host, BuildStream::Source, 0, 3);
        ASSERT_TRUE(std::holds_alternative<Failed>(reply));
        EXPECT_EQ(std::get<Failed>(reply).message, "build file read failed");
        EXPECT_EQ(faults.reads, 1);
    }
    {
        Faults faults;
        faults.write_error = EIO;
        const auto reply = answer(host, WriteRequest{2, BuildStream::Output, 0, {1, 2, 3}});
        ASSERT_TRUE(std::holds_alternative<Failed>(reply));
        EXPECT_EQ(std::get<Failed>(reply).message, "build file write failed");
        EXPECT_EQ(faults.writes, 1);
    }
    EXPECT_EQ(host.length(BuildStream::Output), uint64_t{0});
    EXPECT_EQ(read_build_host(host, BuildStream::Source, 0, 3), (std::vector<uint8_t>{0xff, 0xd8, 0xff}));
}

TEST(PosixSigning, failed_or_invalid_file_metadata_is_reported) {
    TemporaryDirectory directory;
    FileBuildHost host(C2PA_SM_FIXTURE, directory.path / "out.jpg");
    for (auto mode : {Faults::Stat::Error, Faults::Stat::NegativeSize, Faults::Stat::NotRegular}) {
        Faults faults;
        faults.stat = mode;
        const auto reply = answer(host, BuildLengthRequest{1, BuildStream::Source});
        ASSERT_TRUE(std::holds_alternative<Failed>(reply));
        EXPECT_EQ(std::get<Failed>(reply).message, "build file length failed");
        EXPECT_EQ(faults.stats, 1);
    }
    EXPECT_GT(host.length(BuildStream::Source), uint64_t{0});
}

TEST(PosixSigning, failed_sync_preserves_the_destination_and_removes_the_temporary_file) {
    TemporaryDirectory directory;
    const auto destination = directory.path / "out.jpg";
    {
        std::ofstream output(destination);
        output << "keep me";
        ASSERT_TRUE(output);
    }
    {
        Faults faults;
        faults.sync_error = EIO;
        EXPECT_THROW(build_and_sign_file(signing_settings(), C2PA_SM_FIXTURE, destination, fixture_sign),
                     std::runtime_error);
        EXPECT_EQ(faults.syncs, 1);
    }
    std::ifstream preserved(destination);
    EXPECT_EQ(std::string(std::istreambuf_iterator<char>(preserved), {}), "keep me");
    EXPECT_EQ(std::distance(std::filesystem::directory_iterator(directory.path),
                           std::filesystem::directory_iterator{}), 1);
}
