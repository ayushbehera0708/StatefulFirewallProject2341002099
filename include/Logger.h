#ifndef FIREWALL_LOGGER_H
#define FIREWALL_LOGGER_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <memory>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace firewall {

/**
 * @brief Severity levels for asynchronous logging.
 */
enum class LogLevel : uint8_t {
    DEBUG = 0,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

/**
 * @brief Represents an individual log record passed to the background worker.
 */
struct LogMessage {
    LogLevel level;
    std::chrono::system_clock::time_point timestamp;
    std::thread::id thread_id;
    std::string file;
    int line;
    std::string content;
};

/**
 * @brief Configuration parameters for Logger initialization and log rotation.
 */
struct LoggerConfig {
    std::string file_path{"firewall.log"};
    LogLevel min_level{LogLevel::INFO};
    bool log_to_console{true};
    bool log_to_file{true};
    size_t max_file_size_bytes{10 * 1024 * 1024}; // 10 MB
    size_t max_backup_files{5};
    size_t queue_capacity{50000};
};

/**
 * @brief Production-grade asynchronous, thread-safe logging subsystem.
 */
class Logger {
public:
    static Logger& getInstance();

    ~Logger();

    // Prevent copies and moves
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;

    /**
     * @brief Configures and launches the asynchronous logging background thread.
     */
    void init(const LoggerConfig& config);

    /**
     * @brief Posts a log message to the asynchronous processing queue.
     */
    void log(LogLevel level, const char* file, int line, const std::string& message);

    /**
     * @brief Sets the minimum logging threshold.
     */
    void setLogLevel(LogLevel level) noexcept;

    /**
     * @brief Blocks until all queued log messages are committed to disk.
     */
    void flush();

    /**
     * @brief Drains remaining messages and shuts down the background worker thread.
     */
    void shutdown();

    static std::string levelToString(LogLevel level);
    static LogLevel stringToLevel(const std::string& level_str);

private:
    Logger();

    void workerLoop();
    void rotateLogFiles();
    std::string formatLogRecord(const LogMessage& msg) const;

    LoggerConfig config_;
    std::atomic<LogLevel> current_level_{LogLevel::INFO};
    std::atomic<bool> is_running_{false};

    std::queue<LogMessage> queue_;
    std::mutex queue_mutex_;
    std::condition_variable cv_queue_;
    std::condition_variable cv_flush_;

    std::ofstream file_stream_;
    size_t current_file_size_{0};

    std::thread worker_thread_;
};

} // namespace firewall

// Convenience Logging Macros
#define LOG_DEBUG(msg) \
    ::firewall::Logger::getInstance().log(::firewall::LogLevel::DEBUG, __FILE__, __LINE__, msg)

#define LOG_INFO(msg) \
    ::firewall::Logger::getInstance().log(::firewall::LogLevel::INFO, __FILE__, __LINE__, msg)

#define LOG_WARN(msg) \
    ::firewall::Logger::getInstance().log(::firewall::LogLevel::WARNING, __FILE__, __LINE__, msg)

#define LOG_ERROR(msg) \
    ::firewall::Logger::getInstance().log(::firewall::LogLevel::ERROR, __FILE__, __LINE__, msg)

#define LOG_CRITICAL(msg) \
    ::firewall::Logger::getInstance().log(::firewall::LogLevel::CRITICAL, __FILE__, __LINE__, msg)

#endif // FIREWALL_LOGGER_H
