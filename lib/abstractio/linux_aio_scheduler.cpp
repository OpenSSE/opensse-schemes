#include "linux_aio_scheduler.hpp"

#include "utils/utils.hpp"

#include <cassert>
#include <libaio.h>

#include <iostream>

namespace sse {
namespace abstractio {

static constexpr size_t kMaxNr = 128;

LinuxAIOScheduler::LinuxAIOScheduler(const size_t   page_size,
                                     const unsigned nr_events)
    : Scheduler(), m_ioctx(0), m_page_size(page_size), m_stop_flag(false),
      m_submitted_queries_count(0), m_completed_queries_count(0)
{
    memset(&m_ioctx, 0, sizeof(m_ioctx));
    int res = io_setup(nr_events, &m_ioctx);

    if (res != 0) {
        throw std::runtime_error("Error initializing io context: "
                                 + std::to_string(errno) + "(" + strerror(errno)
                                 + ")\n");
    }
    m_notify_thread = std::thread(&LinuxAIOScheduler::notify_loop, this);
}

LinuxAIOScheduler::~LinuxAIOScheduler()
{
    wait_completions();

    io_destroy(m_ioctx);

    // std::cerr << "io_submit: " << m_submit_calls << " calls\n";
    // std::cerr << m_submit_partial << " partial submissions\n";
    // std::cerr << m_submit_EAGAIN << " with full queue\n";
}

void LinuxAIOScheduler::notify_loop()
{
    struct io_event* events = new io_event[kMaxNr];
    struct timespec  timeout;
    timeout.tv_sec  = 0;
    timeout.tv_nsec = 100000000;


    while (!m_stop_flag.load()
           || ((m_completed_queries_count + m_failed_queries_count.load())
               < m_submitted_queries_count.load())) {
        int num_events = io_getevents(m_ioctx, 1, kMaxNr, events, &timeout);

        if (num_events < 0) {
            std::cerr << "Error in io_getevents: " << std::to_string(errno)
                      << "(" << strerror(errno) << ")\n";
        }

        if (num_events > 0) {
            std::lock_guard<std::mutex> guard(m_cv_lock);
            m_waiting_submissions = false;

            m_cv_submission.notify_all();
        }

        for (int i = 0; i < num_events; i++) {
            struct io_event  event = events[i];
            LinuxAIORequest* req   = static_cast<LinuxAIORequest*>(event.data);
            req->notify(event.res);
            delete req;
        }
        m_completed_queries_count += num_events;
    }

    delete[] events;
    std::cerr << "Shut down\n";
}

int LinuxAIOScheduler::check_args(void* buf, size_t len, off_t offset)
{
    if (!utility::is_aligned(buf, m_page_size)) {
        return -EINVAL_UNALIGNED_BUFFER;
    }

    if (len % 512 != 0) {
        return -EINVAL_BUFFERSIZE;
    }

    if (offset % 512 != 0) {
        return -EINVAL_UNALIGNED_ACCESS;
    }

    return 0;
}

void LinuxAIOScheduler::wait_completions()
{
    m_stop_flag = true;

    if (m_notify_thread.joinable()) {
        m_notify_thread.join();
    }
}

int LinuxAIOScheduler::submit_iocbs(struct iocb** iocbs, size_t n_iocbs)
{
    int           res            = -EAGAIN;
    size_t        remaining_subs = n_iocbs;
    struct iocb** iocbs_head     = iocbs;


    while (remaining_subs > 0) {
        res = io_submit(m_ioctx, remaining_subs, iocbs_head);
        // m_submit_calls++;

        if (res >= 0) {
            assert(static_cast<size_t>(res) <= remaining_subs);
            if (static_cast<size_t>(res) != remaining_subs) {
                // m_submit_partial++;
            }
            remaining_subs -= res;
            iocbs_head += res;
        } else if (res == -EAGAIN) {
            // m_submit_EAGAIN++;
            // wait until the submission queue has some space
            std::unique_lock<std::mutex> lock(m_cv_lock);

            m_waiting_submissions = true;
            while (m_waiting_submissions) {
                m_cv_submission.wait(lock);
            }
        } else {
            // m_failed_queries_count.fetch_add(remaining_subs);
            std::cerr << "Submission error: " << res << "\n";
            if (res < 0)
                perror("io_submit");
            else
                fprintf(stderr, "io_submit failed\n");
            return -1;
        }
    }

    return n_iocbs - remaining_subs;
}

int LinuxAIOScheduler::submit_pread(int                     fd,
                                    void*                   buf,
                                    size_t                  len,
                                    off_t                   offset,
                                    void*                   data,
                                    scheduler_callback_type callback)
{
    if (m_stop_flag) {
        return -EINVAL_INVALID_STATE; // the error code is negated, to be
                                      // consistent with the libaio error
                                      // code conventions
    }

    int ret = check_args(buf, len, offset);

    if (ret != 0) {
        return ret;
    }
    struct iocb  iocb;
    struct iocb* iocbs = &iocb;

    uint64_t         query_id = m_submitted_queries_count.fetch_add(1);
    LinuxAIORequest* req
        = new LinuxAIORequest(query_id, data, std::move(callback));

    // std::cerr << "Prep read\n";

    io_prep_pread(&iocb, fd, buf, len, offset);
    iocb.data = req;

    // std::cerr << "Submit IO\n";
    return submit_iocbs(&iocbs, 1);
}

int LinuxAIOScheduler::submit_preads(const std::vector<PReadSumission>& subs)
{
    if (m_stop_flag) {
        return -EINVAL_INVALID_STATE; // the error code is negated, to be
                                      // consistent with the libaio error
                                      // code conventions
    }

    struct iocb** iocbs
        = (struct iocb**)calloc(subs.size(), sizeof(struct iocb*));
    size_t iocbs_count = 0;

    // pre-allocate the actual iocb structures
    struct iocb* flat_iocbs
        = (struct iocb*)calloc(subs.size(), sizeof(struct iocb));


    // fill in all the iocbs needed
    for (const auto& sub : subs) {
        // check that the arguments are well-formed
        if (check_args(sub.buf, sub.len, sub.offset) != 0) {
            continue;
        }

        uint64_t         query_id = m_submitted_queries_count.fetch_add(1);
        LinuxAIORequest* req
            = new LinuxAIORequest(query_id, sub.data, sub.callback);

        io_prep_pread(
            &flat_iocbs[iocbs_count], sub.fd, sub.buf, sub.len, sub.offset);
        flat_iocbs[iocbs_count].data = req;
        iocbs[iocbs_count]           = &flat_iocbs[iocbs_count];
        iocbs_count++;
    }

    // now we have to submit the iocbs
    int ret = submit_iocbs(iocbs, iocbs_count);

    // free the allocated memory
    free(iocbs);
    free(flat_iocbs);

    return ret;
}


int LinuxAIOScheduler::submit_pwrite(int                     fd,
                                     void*                   buf,
                                     size_t                  len,
                                     off_t                   offset,
                                     void*                   data,
                                     scheduler_callback_type callback)
{
    if (m_stop_flag) {
        return -EINVAL_INVALID_STATE; // the error code is negated, to be
                                      // consistent with the libaio error
                                      // code conventions
    }

    if (!utility::is_aligned(buf, m_page_size)) {
        return -EINVAL_UNALIGNED_BUFFER;
    }

    if (len % 512 != 0) {
        return -EINVAL_BUFFERSIZE;
    }

    if (offset % 512 != 0) {
        return -EINVAL_UNALIGNED_ACCESS;
    }

    struct iocb  iocb;
    struct iocb* iocbs = &iocb;

    uint64_t         query_id = m_submitted_queries_count.fetch_add(1);
    LinuxAIORequest* req
        = new LinuxAIORequest(query_id, data, std::move(callback));

    io_prep_pwrite(&iocb, fd, buf, len, offset);
    iocb.data = req;

    return submit_iocbs(&iocbs, 1);
}


template<typename T>
struct destructive_copy_constructible
{
    mutable T value;

    destructive_copy_constructible()
    {
    }

    destructive_copy_constructible(T&& v) : value(std::move(v))
    {
    }

    destructive_copy_constructible(const destructive_copy_constructible<T>& rhs)
        : value(std::move(rhs.value))
    {
    }

    destructive_copy_constructible(destructive_copy_constructible<T>&& rhs)
        = default;

    destructive_copy_constructible& operator=(
        const destructive_copy_constructible<T>& rhs)
        = delete;

    destructive_copy_constructible& operator=(
        destructive_copy_constructible<T>&& rhs)
        = delete;
};

template<typename T>
using dcc_t
    = destructive_copy_constructible<typename std::remove_reference<T>::type>;

template<typename T>
inline dcc_t<T> move_to_dcc(T&& r)
{
    return dcc_t<T>(std::move(r));
}

std::future<ReadBuffer> LinuxAIOScheduler::async_read(int    fd,
                                                      size_t len,
                                                      off_t  offset)
{
    constexpr size_t kMinBufferSize   = 512;
    constexpr size_t kMemoryAlignment = 4096; // 4kB alignment

    std::promise<ReadBuffer> read_promise;

    void* buffer;
    int   ret = posix_memalign((&(buffer)),
                             kMemoryAlignment,
                             std::max(kMemoryAlignment, kMinBufferSize));


    if (ret != 0 || buffer == NULL) {
        throw std::runtime_error("Error when allocating aligned memory: errno "
                                 + std::to_string(ret) + "(" + strerror(ret)
                                 + ")");
    }

    assert(ret == 0);
    assert(buffer != NULL);

    std::future<ReadBuffer> read_future = read_promise.get_future();

    auto prom = move_to_dcc(
        read_promise); // does this hack annoy you? Yeah, me too ...
    // This is due to the fact that std::function must be copy-constructible,
    // which is not possible when we capture a promise, which is only
    // move-constructible. The only other way to do that is to rely on a
    // shared_pointer, at the cost of an extra memory allocation.
    // This solution comes from https://stackoverflow.com/a/57694904

    auto cb = [prom](void* buffer, int64_t len) {
        ReadBuffer res;
        res.buf = buffer;
        res.len = len;
        prom.value.set_value(res);
    };

    ret = submit_pread(fd, buffer, len, offset, buffer, std::move(cb));

    if (ret != 1) {
        free(buffer);

        throw std::runtime_error(
            "Error when submitting the read async IO: errno "
            + std::to_string(ret) + "(" + strerror(ret) + ")");
    }

    return read_future;
}


std::future<int> LinuxAIOScheduler::async_write(int    fd,
                                                void*  buf,
                                                size_t len,
                                                off_t  offset)
{
    std::promise<int> write_promise;


    std::future<int> write_future = write_promise.get_future();

    auto prom = move_to_dcc(
        write_promise); // does this hack annoy you? Yeah, me too ...

    auto cb = [prom](void* /*buffer*/, int64_t len) {
        // set the len of the write
        prom.value.set_value(len);
    };

    int ret = submit_pwrite(fd, buf, len, offset, buf, cb);

    if (ret != 1) {
        throw std::runtime_error("Error when submitting the read async IO: "
                                 + std::to_string(ret));
    }

    return write_future;
}
} // namespace abstractio
} // namespace sse
