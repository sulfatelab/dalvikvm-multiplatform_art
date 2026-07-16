/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ART_RUNTIME_BASE_MUTEX_INL_H_
#define ART_RUNTIME_BASE_MUTEX_INL_H_

#include <inttypes.h>

#include "mutex.h"

#include "base/utils.h"
#include "base/value_object.h"
#include "thread.h"

#if ART_USE_FUTEXES
#include <linux/futex.h>
#include <sys/syscall.h>
#if defined(_WIN32)
#include <windows.h>
#endif
#endif  // ART_USE_FUTEXES

#define CHECK_MUTEX_CALL(call, args) CHECK_PTHREAD_CALL(call, args, name_)

namespace art HIDDEN {

#if ART_USE_FUTEXES
#if defined(_WIN32)
// WaitOnAddress-based futex. Supports WAIT/WAKE used by ART mutexes.
// FUTEX_* constants are provided by linux/futex.h shim on Windows.
static inline int futex(volatile int *uaddr, int op, int val, const struct timespec *timeout,
                        volatile int *uaddr2, int val3) {
  (void)uaddr2; (void)val3;
  // Strip PRIVATE bit if present.
  int base_op = op & 0x7f; // ignore flags in high bits roughly
  // Linux FUTEX_PRIVATE_FLAG is 128; ops used: WAIT=0, WAKE=1, WAIT_BITSET=9, WAKE_BITSET=10
  int cmd = op & 0xf; // good enough for ART's usage patterns
  if ((op & 128) != 0) {
    // private flag; ignore
  }
  if (cmd == 0 /*FUTEX_WAIT*/ || cmd == 9 /*FUTEX_WAIT_BITSET*/) {
    DWORD ms = INFINITE;
    if (timeout != nullptr) {
      // Relative timeout (ART always passes relative timespeces into futex()).
      long long total_ms = (long long)timeout->tv_sec * 1000LL +
                           (timeout->tv_nsec + 999999LL) / 1000000LL;  // round up
      if (total_ms < 0) total_ms = 0;
      // If a positive timeout rounded to 0ms, wait at least 1ms so we don't spin forever.
      if (total_ms == 0 && (timeout->tv_sec > 0 || timeout->tv_nsec > 0)) total_ms = 1;
      if (total_ms > 0xffffffffLL) ms = INFINITE;
      else ms = (DWORD)total_ms;
    }
    // Snapshot expected value for WaitOnAddress compare.
    int expected = val;
    int observed = *uaddr;
    if (observed != expected) {
      errno = EAGAIN;
      return -1;
    }
    if (!WaitOnAddress((PVOID)uaddr, &expected, sizeof(int), ms)) {
      DWORD err = GetLastError();
      if (err == ERROR_TIMEOUT || err == ERROR_TIMEOUT /* same */) {
        errno = ETIMEDOUT;
      } else if (err == 0 || err == ERROR_SUCCESS) {
        // Some wine builds return false without setting last error on timeout.
        errno = ETIMEDOUT;
      } else {
        errno = EINTR;
      }
      return -1;
    }
    return 0;
  }
  if (cmd == 1 /*FUTEX_WAKE*/ || cmd == 10 /*FUTEX_WAKE_BITSET*/) {
    if (val == 1) {
      WakeByAddressSingle((PVOID)uaddr);
    } else {
      WakeByAddressAll((PVOID)uaddr);
    }
    return val; // "woken" count unknown; ART ignores exact count mostly
  }
  // Best-effort requeue: wake all on uaddr.
  if (cmd == 3 /*REQUEUE*/ || cmd == 4 /*CMP_REQUEUE*/) {
    WakeByAddressAll((PVOID)uaddr);
    if (uaddr2) WakeByAddressAll((PVOID)uaddr2);
    return 0;
  }
  errno = ENOSYS;
  return -1;
}
#else
static inline int futex(volatile int *uaddr, int op, int val, const struct timespec *timeout,
                        volatile int *uaddr2, int val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}
#endif
#endif  // ART_USE_FUTEXES

// The following isn't strictly necessary, but we want updates on Atomic<pid_t> to be lock-free.
// TODO: Use std::atomic::is_always_lock_free after switching to C++17 atomics.
static_assert(sizeof(pid_t) <= sizeof(int32_t), "pid_t should fit in 32 bits");

static inline pid_t SafeGetTid(const Thread* self) {
  if (self != nullptr) {
    return self->GetTid();
  } else {
    return GetTid();
  }
}

static inline void CheckUnattachedThread(LockLevel level) NO_THREAD_SAFETY_ANALYSIS {
  // The check below enumerates the cases where we expect not to be able to check the validity of
  // locks on a thread. Lock checking is disabled to avoid deadlock when checking shutdown lock.
  // TODO: tighten this check.
  CHECK(!Locks::IsSafeToCallAbortRacy() ||
        // Used during thread creation to avoid races with runtime shutdown. Thread::Current not
        // yet established.
        level == kRuntimeShutdownLock ||
        // Thread Ids are allocated/released before threads are established.
        level == kAllocatedThreadIdsLock ||
        // Thread LDT's are initialized without Thread::Current established.
        level == kModifyLdtLock ||
        // Threads are unregistered while holding the thread list lock, during this process they
        // no longer exist and so we expect an unlock with no self.
        level == kThreadListLock ||
        // Ignore logging which may or may not have set up thread data structures.
        level == kLoggingLock ||
        // When transitioning from suspended to runnable, a daemon thread might be in
        // a situation where the runtime is shutting down. To not crash our debug locking
        // mechanism we just pass null Thread* to the MutexLock during that transition
        // (see Thread::TransitionFromSuspendedToRunnable).
        level == kThreadSuspendCountLock ||
        // Avoid recursive death.
        level == kAbortLock ||
        // Locks at the absolute top of the stack can be locked at any time.
        level == kTopLockLevel ||
        // The unexpected signal handler may be catching signals from any thread.
        level == kUnexpectedSignalLock)
      << level;
}

inline void BaseMutex::RegisterAsLocked(Thread* self, bool check) {
  if (UNLIKELY(self == nullptr)) {
    if (check) {
      CheckUnattachedThread(level_);
    }
  } else {
    RegisterAsLockedImpl(self, level_, check);
  }
}

inline void BaseMutex::RegisterAsLockedImpl(Thread* self, LockLevel level, bool check) {
  DCHECK(self != nullptr);
  DCHECK_EQ(level_, level);
  // It would be nice to avoid this condition checking in the non-debug case,
  // but that would make the various methods that check if a mutex is held not
  // work properly for thread wait locks. Since the vast majority of lock
  // acquisitions are not thread wait locks, this check should not be too
  // expensive.
  if (UNLIKELY(level == kThreadWaitLock) && self->GetHeldMutex(kThreadWaitLock) != nullptr) {
    level = kThreadWaitWakeLock;
  }
  if (check) {
    // Check if a bad Mutex of this level or lower is held.
    bool bad_mutexes_held = false;
    // Specifically allow a kTopLockLevel lock to be gained when the current thread holds the
    // mutator_lock_ exclusive. This is because we suspending when holding locks at this level is
    // not allowed and if we hold the mutator_lock_ exclusive we must unsuspend stuff eventually
    // so there are no deadlocks.
    if (level == kTopLockLevel &&
        Locks::mutator_lock_->IsSharedHeld(self) &&
        !Locks::mutator_lock_->IsExclusiveHeld(self)) {
      LOG(ERROR) << "Lock level violation: holding \"" << Locks::mutator_lock_->name_ << "\" "
                  << "(level " << kMutatorLock << " - " << static_cast<int>(kMutatorLock)
                  << ") non-exclusive while locking \"" << name_ << "\" "
                  << "(level " << level << " - " << static_cast<int>(level) << ") a top level"
                  << "mutex. This is not allowed.";
      bad_mutexes_held = true;
    } else if (this == Locks::mutator_lock_ && self->GetHeldMutex(kTopLockLevel) != nullptr) {
      LOG(ERROR) << "Lock level violation. Locking mutator_lock_ while already having a "
                 << "kTopLevelLock (" << self->GetHeldMutex(kTopLockLevel)->name_ << "held is "
                 << "not allowed.";
      bad_mutexes_held = true;
    }
    for (int i = level; i >= 0; --i) {
      LockLevel lock_level_i = static_cast<LockLevel>(i);
      BaseMutex* held_mutex = self->GetHeldMutex(lock_level_i);
      if (level == kTopLockLevel &&
          lock_level_i == kMutatorLock &&
          Locks::mutator_lock_->IsExclusiveHeld(self)) {
        // This is checked above.
        continue;
      } else if (UNLIKELY(held_mutex != nullptr) && lock_level_i != kAbortLock) {
        LOG(ERROR) << "Lock level violation: holding \"" << held_mutex->name_ << "\" "
                   << "(level " << lock_level_i << " - " << i
                   << ") while locking \"" << name_ << "\" "
                   << "(level " << level << " - " << static_cast<int>(level) << ")";
        if (lock_level_i > kAbortLock) {
          // Only abort in the check below if this is more than abort level lock.
          bad_mutexes_held = true;
        }
      }
    }
    if (gAborting == 0) {  // Avoid recursive aborts.
      CHECK(!bad_mutexes_held);
    }
  }
  // Don't record monitors as they are outside the scope of analysis. They may be inspected off of
  // the monitor list.
  if (level != kMonitorLock) {
    self->SetHeldMutex(level, this);
  }
}

inline void BaseMutex::RegisterAsUnlocked(Thread* self) {
  if (UNLIKELY(self == nullptr)) {
    if (kDebugLocking) {
      CheckUnattachedThread(level_);
    }
  } else {
    RegisterAsUnlockedImpl(self, level_);
  }
}

inline void BaseMutex::RegisterAsUnlockedImpl(Thread* self, LockLevel level) {
  DCHECK(self != nullptr);
  DCHECK_EQ(level_, level);
  if (level != kMonitorLock) {
    if (UNLIKELY(level == kThreadWaitLock) && self->GetHeldMutex(kThreadWaitWakeLock) == this) {
      level = kThreadWaitWakeLock;
    }
    if (kDebugLocking && gAborting == 0) {  // Avoid recursive aborts.
      if (level == kThreadWaitWakeLock) {
        CHECK(self->GetHeldMutex(kThreadWaitLock) != nullptr) << "Held " << kThreadWaitWakeLock << " without " << kThreadWaitLock;;
      }
      CHECK(self->GetHeldMutex(level) == this) << "Unlocking on unacquired mutex: " << name_;
    }
    self->SetHeldMutex(level, nullptr);
  }
}

inline void ReaderWriterMutex::SharedLock(Thread* self) {
  DCHECK(self == nullptr || self == Thread::Current());
#if ART_USE_FUTEXES
  bool done = false;
  do {
    int32_t cur_state = state_.load(std::memory_order_relaxed);
    if (LIKELY(cur_state >= 0)) {
      // Add as an extra reader.
      done = state_.CompareAndSetWeakAcquire(cur_state, cur_state + 1);
    } else {
      HandleSharedLockContention(self, cur_state);
    }
  } while (!done);
#else
  CHECK_MUTEX_CALL(pthread_rwlock_rdlock, (&rwlock_));
#endif
  DCHECK(GetExclusiveOwnerTid() == 0 || GetExclusiveOwnerTid() == -1);
  RegisterAsLocked(self);
  AssertSharedHeld(self);
}

inline void ReaderWriterMutex::SharedUnlock(Thread* self) {
  DCHECK(self == nullptr || self == Thread::Current());
  DCHECK(GetExclusiveOwnerTid() == 0 || GetExclusiveOwnerTid() == -1);
  AssertSharedHeld(self);
  RegisterAsUnlocked(self);
#if ART_USE_FUTEXES
  bool done = false;
  do {
    int32_t cur_state = state_.load(std::memory_order_relaxed);
    if (LIKELY(cur_state > 0)) {
      // Reduce state by 1 and impose lock release load/store ordering.
      // Note, the num_contenders_ load below musn't reorder before the CompareAndSet.
      done = state_.CompareAndSetWeakSequentiallyConsistent(cur_state, cur_state - 1);
      if (done && (cur_state - 1) == 0) {  // Weak CAS may fail spuriously.
        if (num_contenders_.load(std::memory_order_seq_cst) > 0) {
          // Wake any exclusive waiters as there are now no readers.
          futex(state_.Address(), FUTEX_WAKE_PRIVATE, kWakeAll, nullptr, nullptr, 0);
        }
      }
    } else {
      LOG(FATAL) << "Unexpected state_:" << cur_state << " for " << name_;
    }
  } while (!done);
#else
  CHECK_MUTEX_CALL(pthread_rwlock_unlock, (&rwlock_));
#endif
}

inline bool Mutex::IsExclusiveHeld(const Thread* self) const {
  DCHECK(self == nullptr || self == Thread::Current());
  bool result = (GetExclusiveOwnerTid() == SafeGetTid(self));
  if (kDebugLocking) {
    // Debug check that if we think it is locked we have it in our held mutexes.
    if (result && self != nullptr && level_ != kMonitorLock && !gAborting) {
      if (level_ == kThreadWaitLock && self->GetHeldMutex(kThreadWaitLock) != this) {
        CHECK_EQ(self->GetHeldMutex(kThreadWaitWakeLock), this);
      } else {
        CHECK_EQ(self->GetHeldMutex(level_), this);
      }
    }
  }
  return result;
}

inline pid_t Mutex::GetExclusiveOwnerTid() const {
  return exclusive_owner_.load(std::memory_order_relaxed);
}

inline void Mutex::AssertExclusiveHeld(const Thread* self) const {
  if (kDebugLocking && (gAborting == 0)) {
    CHECK(IsExclusiveHeld(self)) << *this;
  }
}

inline void Mutex::AssertHeld(const Thread* self) const {
  AssertExclusiveHeld(self);
}

inline bool ReaderWriterMutex::IsExclusiveHeld(const Thread* self) const {
  DCHECK(self == nullptr || self == Thread::Current());
  bool result = (GetExclusiveOwnerTid() == SafeGetTid(self));
  if (kDebugLocking) {
    // Verify that if the pthread thinks we own the lock the Thread agrees.
    if (self != nullptr && result)  {
      CHECK_EQ(self->GetHeldMutex(level_), this);
    }
  }
  return result;
}

inline pid_t ReaderWriterMutex::GetExclusiveOwnerTid() const {
#if ART_USE_FUTEXES
  int32_t state = state_.load(std::memory_order_relaxed);
  if (state == 0) {
    return 0;  // No owner.
  } else if (state > 0) {
    return -1;  // Shared.
  } else {
    return exclusive_owner_.load(std::memory_order_relaxed);
  }
#else
  return exclusive_owner_.load(std::memory_order_relaxed);
#endif
}

inline void ReaderWriterMutex::AssertExclusiveHeld(const Thread* self) const {
  if (kDebugLocking && (gAborting == 0)) {
    CHECK(IsExclusiveHeld(self)) << *this;
  }
}

inline void ReaderWriterMutex::AssertWriterHeld(const Thread* self) const {
  AssertExclusiveHeld(self);
}

inline void MutatorMutex::TransitionFromRunnableToSuspended(Thread* self) {
  AssertSharedHeld(self);
  RegisterAsUnlockedImpl(self, kMutatorLock);
}

inline void MutatorMutex::TransitionFromSuspendedToRunnable(Thread* self) {
  RegisterAsLockedImpl(self, kMutatorLock, kDebugLocking);
  AssertSharedHeld(self);
}

inline ReaderMutexLock::ReaderMutexLock(Thread* self, ReaderWriterMutex& mu)
    : self_(self), mu_(mu) {
  mu_.SharedLock(self_);
}

inline ReaderMutexLock::~ReaderMutexLock() {
  mu_.SharedUnlock(self_);
}

}  // namespace art

#endif  // ART_RUNTIME_BASE_MUTEX_INL_H_
