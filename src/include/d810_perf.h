#ifndef D810_PERF_H
#define D810_PERF_H

#include <chrono>
#include <cstdint>

// C++17's steady_clock is monotonic on every supported platform and keeps the
// Cython modules free of OS-specific clock APIs in their hot paths.
static inline std::uint64_t d810_perf_now_ns() noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count()
    );
}

#endif  // D810_PERF_H
