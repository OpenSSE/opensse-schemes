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

void LinuxAIOScheduler::wait_completions()
{
    m_stop_flag = true;

    if (m_notify_thread.joinable()) {
        m_notify_thread.join();
    }
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

    // std::cerr << "Prep read\n";

    io_prep_pread(&iocb, fd, buf, len, offset);
    iocb.data = req;

    // std::cerr << "Submit IO\n";

    int    res             = -EAGAIN;
    size_t tentative_count = 0;

    while (res == -EAGAIN) {
        tentative_count++;

        res = io_submit(m_ioctx, 1, &iocbs);
    }

    if (res != 1) {
        m_failed_queries_count.fetch_add(1);
        std::cerr << "Submission error: " << res << "\n";
        if (res < 0)
            perror("io_submit");
        else
            fprintf(stderr, "io_submit failed\n");
        return -1;
    } // std::cerr << "IO Submitted: " << res << "\n";

    return res;
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


    int    res             = -EAGAIN;
    size_t tentative_count = 0;

    while (res == -EAGAIN) {
        tentative_count++;

        res = io_submit(m_ioctx, 1, &iocbs);
    }


    if (res != 1) {
        m_failed_queries_count.fetch_add(1);
        std::cerr << "Submission error: " << res << "\n";
        if (res < 0)
            perror("io_submit");
        else
            fprintf(stdout, "io_submit failed\n");
        return -1;
    }
    return res;
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

    auto cb = [prom](void* buffer, int64_t len) {
        ReadBuffer res;
        res.buf = buffer;
        res.len = len;
        prom.value.set_value(res);
    };

    ret = submit_pread(fd, buffer, len, offset, buffer, cb);

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
