//    Copyright (c) 2012 Jakob Progsch, Václav Zeman
//
//    This software is provided 'as-is', without any express or implied
//    warranty. In no event will the authors be held liable for any damages
//    arising from the use of this software.
//
//    Permission is granted to anyone to use this software for any purpose,
//    including commercial applications, and to alter it and redistribute it
//    freely, subject to the following restrictions:
//
//    1. The origin of this software must not be misrepresented; you must not
//    claim that you wrote the original software. If you use this software
//    in a product, an acknowledgment in the product documentation would be
//    appreciated but is not required.
//
//    2. Altered source versions must be plainly marked as such, and must not be
//    misrepresented as being the original software.
//
//    3. This notice may not be removed or altered from any source
//    distribution.

#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <vector>
#include <queue>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <stdexcept>
#include <iostream>
#include <unordered_map>

class ThreadPool {
public:
    ThreadPool(uint32_t);
    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args)
    -> std::future<typename std::result_of<F(Args...)>::type>;
    
    void join();
    ~ThreadPool();
private:
    virtual void register_thread(uint32_t id_pool);
    
    // need to keep track of threads so we can join them
    std::vector< std::thread > workers;
    // the task queue
    std::queue< std::function<void()> > tasks;
    
    size_t max_tasks_size_;
    
    // synchronization
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

class IdentifiedThreadPool : public ThreadPool
{
public:
    IdentifiedThreadPool(uint32_t threads);
    
    uint32_t get_thread_index() const;

private:
    virtual void register_thread(uint32_t id_pool);

    std::mutex setup_mutex_;
    std::unordered_map<std::thread::id, uint32_t> thread_indexes_;
};

// the constructor just launches some amount of workers
inline ThreadPool::ThreadPool(uint32_t threads)
: max_tasks_size_(0), stop(false)
{
    for(uint32_t i = 0;i<threads;++i)
        workers.emplace_back(
                             [this, &i]
                             {
                                 register_thread(i);
                                 for(;;)
                                 {
                                     std::function<void()> task;
                                     
                                     {
                                         std::unique_lock<std::mutex> lock(this->queue_mutex);
                                         this->condition.wait(lock,
                                                              [this]{ return this->stop || !this->tasks.empty(); });
                                         if(this->stop && this->tasks.empty())
                                             return;
                                         
                                         max_tasks_size_ = std::max(max_tasks_size_, tasks.size());
                                         task = std::move(this->tasks.front());
                                         this->tasks.pop();
                                     }
                                     
                                     task();
                                 }
                             }
                             );
}

inline void ThreadPool::register_thread(uint32_t id_pool)
{
}

// add new work item to the pool
template<class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args)
-> std::future<typename std::result_of<F(Args...)>::type>
{
    using return_type = typename std::result_of<F(Args...)>::type;
    
    auto task = std::make_shared< std::packaged_task<return_type()> >(
                                                                      std::bind(std::forward<F>(f), std::forward<Args>(args)...)
                                                                      );
    
    std::future<return_type> res = task->get_future();
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        
        // don't allow enqueueing after stopping the pool
        if(stop)
            throw std::runtime_error("enqueue on stopped ThreadPool");
        
        tasks.emplace([task](){ (*task)(); });
    }
    condition.notify_one();
    return res;
}

inline void ThreadPool::join()
{
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
//        std::cout << "Current queue size: " << tasks.size() << std::endl;
        stop = true;
    }
    condition.notify_all();
    for(std::thread &worker: workers)
    {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
//    std::cout << "Maximum queue size: " << max_tasks_size_ << std::endl;
}

// the destructor joins all threads
inline ThreadPool::~ThreadPool()
{
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
//        std::cout << "Current queue size: " << tasks.size() << std::endl;
        stop = true;
    }
    condition.notify_all();
    for(std::thread &worker: workers)
    {
        if (worker.joinable()) {
            worker.join();
        }
    }
    
//    std::cout << "Maximum queue size: " << max_tasks_size_ << std::endl;
}

inline IdentifiedThreadPool::IdentifiedThreadPool(uint32_t threads) :
    ThreadPool(threads), thread_indexes_(threads)
{
    
}

inline void IdentifiedThreadPool::register_thread(uint32_t id_pool)
{
    std::unique_lock<std::mutex> lock(setup_mutex_);
    
    thread_indexes_[std::this_thread::get_id()] = id_pool;
}

inline uint32_t IdentifiedThreadPool::get_thread_index() const
{
    return thread_indexes_.at(std::this_thread::get_id());
}

#endif