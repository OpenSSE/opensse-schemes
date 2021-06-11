#pragma once

#include "configure.hpp"

#ifdef HAS_LIBAIO

#include "abstractio/scheduler.hpp"

#include <libaio.h>

#include <atomic>
#include <thread>
#include <vector>

namespace sse {
namespace abstractio {


class LinuxAIOScheduler : public Scheduler
{
public:
    LinuxAIOScheduler(const size_t page_size, const unsigned nr_events);
    ~LinuxAIOScheduler();

    void wait_completions() override;

    int submit_pread(int                     fd,
                     void*                   buf,
                     size_t                  len,
                     off_t                   offset,
                     void*                   data,
                     scheduler_callback_type callback) override;

    int submit_preads(const std::vector<PReadSumission>& subs) override;

    int submit_pwrite(int                     fd,
                      void*                   buf,
                      size_t                  len,
                      off_t                   offset,
                      void*                   data,
                      scheduler_callback_type callback) override;

    Scheduler* duplicate() const override;

private:
    void notify_loop();

    int check_args(void* buf, size_t len, off_t offset) const;

    size_t submit_iocbs(struct iocb** iocbs, size_t n_iocbs);


    struct LinuxAIORequest
    {
        size_t                  m_id;
        void*                   m_user_data;
        scheduler_callback_type m_callback;

        LinuxAIORequest(size_t id, void* user_data, scheduler_callback_type cb)
            : m_id(id), m_user_data(user_data), m_callback(std::move(cb)){};

        void notify(int64_t len)
        {
            m_callback(m_user_data, len);
        }
    };

    io_context_t   m_ioctx;
    const size_t   m_page_size;
    const unsigned m_nr_events;
    // std::vector<LinuxAIOSchedulerState> m_state;

    std::thread       m_notify_thread;
    std::atomic<bool> m_stop_flag;

    std::atomic<uint64_t> m_submitted_queries_count;
    uint64_t              m_completed_queries_count;
    std::atomic<uint64_t> m_failed_queries_count;

    std::mutex              m_cv_lock;
    std::condition_variable m_cv_submission;
    bool                    m_waiting_submissions{false};

#ifdef LOG_AIO_SCHEDULER_STATS
    std::atomic_size_t m_submit_calls{0};
    std::atomic_size_t m_submit_EAGAIN{0};
    std::atomic_size_t m_submit_partial{0};
#endif
};

} // namespace abstractio
} // namespace sse

#endif // HAS_LIBAIO