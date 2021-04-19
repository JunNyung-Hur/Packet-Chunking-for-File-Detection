// Copyright (c) 2016-2020 AlertAvert.com. All rights reserved.
// Created by M. Massenzio (marco@alertavert.com)

#ifndef THREADSAFE_QUEUE_HPP
#define THREADSAFE_QUEUE_HPP

#include <algorithm>
#include <iostream>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>

class non_empty_queue : public std::exception {
  std::string what_;
 public:
  explicit non_empty_queue(std::string msg) { what_ = std::move(msg); }
  const char* what() const noexcept override  { return what_.c_str(); }
};


template<typename T>
class ThreadsafeQueue {
  std::queue<T> queue_;
  mutable std::mutex mutex_;

  // Moved out of public interface to prevent races between this
  // and pop().
  [[nodiscard]] bool empty() const {
    return queue_.empty();
  }

 public:
  ThreadsafeQueue() = default;
  ThreadsafeQueue(const ThreadsafeQueue<T> &) = delete ;
  ThreadsafeQueue& operator=(const ThreadsafeQueue<T> &) = delete ;

  ThreadsafeQueue(ThreadsafeQueue<T>&& other) noexcept(false) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!empty()) {
      throw non_empty_queue("Moving into a non-empty queue");
    }
    queue_ = std::move(other.queue_);
  }

  virtual ~ThreadsafeQueue() noexcept(false) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!empty()) {
      throw non_empty_queue("Destroying a non-empty queue");
    }
  }

  [[nodiscard]] unsigned long size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return queue_.size();
  }

  std::optional<T> pop() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (queue_.empty()) {
      return {};
    }
    T tmp = queue_.front();
    queue_.pop();
    return tmp;
  }

  void push(const T &item) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(item);
  }
};
#endif