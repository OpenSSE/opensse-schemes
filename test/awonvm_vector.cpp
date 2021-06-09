#include <sse/schemes/abstractio/awonvm_vector.hpp>
#include <sse/schemes/abstractio/scheduler.hpp>
#include <sse/schemes/utils/utils.hpp>

#include <gtest/gtest.h>

namespace sse {
namespace abstractio {
const std::string test_file = "test_awonm_vector.bin";

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

constexpr size_t kPageSize = 4096;

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
            return make_linux_aio_scheduler(kPageSize, 128);
#else
            return std::unique_ptr<Scheduler>(nullptr);
#endif
        case ThreadPoolSchedulerCached:
        case ThreadPoolSchedulerDirect:
            return std::unique_ptr<Scheduler>(make_thread_pool_aio_scheduler());
        }
    }
};

constexpr size_t kTestVecSize = 1000;

TEST_P(AWONVMVectorTest, build_and_get)
{
    bool direct_io = (GetParam() == ThreadPoolSchedulerCached) ? false : true;

    // create the vector
    {
        awonvm_vector<uint64_t, kPageSize> vec(
            test_file, get_scheduler(), direct_io);


        __attribute__((aligned(kPageSize))) uint64_t i = 0;
        for (; i < kTestVecSize; i++) {
            vec.push_back(i);
        }

        vec.commit();
    }

    {
        awonvm_vector<uint64_t, kPageSize> vec(
            test_file, get_scheduler(), direct_io);

        ASSERT_TRUE(vec.is_committed());

        for (uint64_t i = 0; i < kTestVecSize; i++) {
            ASSERT_EQ(vec.get(i), i);
        }
    }
}

TEST_P(AWONVMVectorTest, async_build_and_get)
{
    bool direct_io = (GetParam() == ThreadPoolSchedulerCached) ? false : true;

    // create the vector
    {
        awonvm_vector<uint64_t, kPageSize> vec(
            test_file, get_scheduler(), direct_io);


        __attribute__((aligned(kPageSize))) uint64_t i = 0;
        for (; i < kTestVecSize; i++) {
            vec.async_push_back(i);
        }

        std::cerr << "Commit\n";
        vec.commit();
    }

    {
        awonvm_vector<uint64_t, kPageSize> vec(
            test_file, get_scheduler(), direct_io);

        ASSERT_TRUE(vec.is_committed());

        for (uint64_t i = 0; i < kTestVecSize; i++) {
            vec.async_get(i, [i](std::unique_ptr<uint64_t> value) {
                (void)i;
                (void)value;
                // ASSERT_EQ(*value, i);
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