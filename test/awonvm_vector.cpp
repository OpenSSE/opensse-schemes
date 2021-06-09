#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/abstractio/scheduler.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <gtest/gtest.h>

namespace sse {
namespace abstractio {

constexpr size_t kPageSize = 4096;

const std::string test_file = "test_awonm_vector.bin";

class test_payload
{
public:
    test_payload()
    {
        std::fill(content.begin(), content.end(), 0xFFFFFFFFFFFFFFFF);
    }

    explicit test_payload(uint64_t i)
    {
        std::fill(content.begin(), content.end(), i);
    }

    bool operator==(const test_payload& p) const
    {
        return content == p.content;
    }

private:
    std::array<uint64_t, kPageSize / sizeof(uint64_t)> content;
};

void silent_cleanup()
{
    utility::is_file(test_file);

    utility::remove_file(test_file);
}

void cleanup()
{
    ASSERT_TRUE(utility::is_file(test_file));

    ASSERT_TRUE(utility::remove_file(test_file));
}


enum AWONVMVectorTestScheduler
{
    LinuxAIOScheduler = 1,
    ThreadPoolSchedulerCached,
    ThreadPoolSchedulerDirect
};

class AWONVMVectorTest
    : public testing::TestWithParam<AWONVMVectorTestScheduler>
{
    void SetUp() override
    {
        silent_cleanup();
    }
    void TearDown() override
    {
        cleanup();
    }

public:
    std::unique_ptr<Scheduler> get_scheduler() const
    {
        switch (GetParam()) {
        case LinuxAIOScheduler:
#ifdef HAS_LIBAIO
            return std::unique_ptr<Scheduler>(
                make_linux_aio_scheduler(kPageSize, 128));
#else
            return std::unique_ptr<Scheduler>(nullptr);
#endif
        case ThreadPoolSchedulerCached:
        case ThreadPoolSchedulerDirect:
            return std::unique_ptr<Scheduler>(make_thread_pool_aio_scheduler());

        default:
            return std::unique_ptr<Scheduler>(nullptr);
        }
    }
};

constexpr size_t kTestVecSize = 1000;

TEST_P(AWONVMVectorTest, build_and_get)
{
    bool direct_io = (GetParam() == ThreadPoolSchedulerCached) ? false : true;

    // create the vector
    {
        awonvm_vector<test_payload, kPageSize> vec(
            test_file, get_scheduler(), direct_io);


        uint64_t i = 0;
        for (; i < kTestVecSize; i++) {
            __attribute__((aligned(kPageSize))) test_payload payload(i);

            vec.push_back(payload);
        }

        vec.commit();
    }

    {
        awonvm_vector<test_payload, kPageSize> vec(
            test_file, get_scheduler(), direct_io);

        ASSERT_TRUE(vec.is_committed());

        for (uint64_t i = 0; i < kTestVecSize; i++) {
            ASSERT_EQ(vec.get(i), test_payload(i));
        }
    }
}

TEST_P(AWONVMVectorTest, async_build_and_get)
{
    bool direct_io = (GetParam() == ThreadPoolSchedulerCached) ? false : true;

    // create the vector
    {
        awonvm_vector<test_payload, kPageSize> vec(
            test_file, get_scheduler(), direct_io);


        uint64_t i = 0;
        for (; i < kTestVecSize; i++) {
            __attribute__((aligned(kPageSize))) test_payload payload(i);
            vec.async_push_back(payload);
        }

        vec.commit();
    }

    ASSERT_TRUE(utility::is_file(test_file));
    {
        awonvm_vector<test_payload, kPageSize> vec(
            test_file, get_scheduler(), direct_io);

        ASSERT_TRUE(vec.is_committed());

        for (uint64_t i = 0; i < kTestVecSize; i++) {
            vec.async_get(i, [i](std::unique_ptr<test_payload> value) {
                (void)i;
                (void)value;
                ASSERT_TRUE(value);
                ASSERT_EQ(*value, test_payload(i));
            });
        }
    }
}


INSTANTIATE_TEST_SUITE_P(AWONVMVectorTest,
                         AWONVMVectorTest,
                         testing::Values(ThreadPoolSchedulerCached,
                                         ThreadPoolSchedulerDirect
#ifdef HAS_LIBAIO
                                         ,
                                         LinuxAIOScheduler
#endif
                                         ));


} // namespace abstractio
} // namespace sse