#include "Logger.h"

#include <cstdio>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace firewall {

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger() = default;

Logger::~Logger() {
    shutdown();
}

void Logger::init(const LoggerConfig& config) {
    if (is_running_.load()) {
        shutdown();
    }

    config_ = config;
    current_level_.store(config.min_level);

    if (config_.log_to_file && !config_.file_path.empty()) {
        // Open file in append mode
        file_stream_.open(config_.file_path, std::ios::out | std::ios::app);
        if (file_stream_.is_open()) {
            file_stream_.seekp(0, std::ios::end);
            current_file_size_ = static_cast<size_t>(file_stream_.tellp());
        } else {
            std::cerr << "[Logger] Failed to open log file: " << config_.file_path << std::endl;
        }
    }

    is_running_.store(true);
    worker_thread_ = std::thread(&Logger::workerLoop, this);
}

void Logger::setLogLevel(LogLevel level) noexcept {
    current_level_.store(level);
}

void Logger::log(LogLevel level, const char* file, int line, const std::string& message) {
    if (level < current_level_.load(std::memory_order_relaxed)) {
        return;
    }

    // Extract filename from full path
    std::string filename(file ? file : "");
    size_t last_slash = filename.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        filename = filename.substr(last_slash + 1);
    }

    LogMessage msg{
        level,
        std::chrono::system_clock::now(),
        std::this_thread::get_id(),
        std::move(filename),
        line,
        message
    };

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        if (queue_.size() >= config_.queue_capacity) {
            // Queue capacity reached under extreme load: drop oldest message
            queue_.pop();
        }
        queue_.push(std::move(msg));
    }
    cv_queue_.notify_one();
}

void Logger::flush() {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    cv_flush_.wait(lock, [this]() {
        return queue_.empty();
    });
    if (file_stream_.is_open()) {
        file_stream_.flush();
    }
}

void Logger::shutdown() {
    if (!is_running_.exchange(false)) {
        return;
    }

    cv_queue_.notify_all();
    if (worker_thread_.joinable()) {
        worker_thread_.join();
    }

    // Flush any remaining records to disk
    std::queue<LogMessage> remaining;
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        remaining.swap(queue_);
    }

    while (!remaining.empty()) {
        const auto& msg = remaining.front();
        std::string record = formatLogRecord(msg);
        if (config_.log_to_console) {
            std::cout << record;
        }
        if (file_stream_.is_open()) {
            file_stream_ << record;
            current_file_size_ += record.size();
        }
        remaining.pop();
    }

    if (file_stream_.is_open()) {
        file_stream_.flush();
        file_stream_.close();
    }
}

void Logger::rotateLogFiles() {
    if (!file_stream_.is_open() || config_.max_backup_files == 0) {
        return;
    }

    file_stream_.close();

    namespace fs = std::filesystem;
    std::error_code ec;

    // Delete oldest backup if it exists
    std::string oldest = config_.file_path + "." + std::to_string(config_.max_backup_files);
    if (fs::exists(oldest, ec)) {
        fs::remove(oldest, ec);
    }

    // Shift intermediate backup files: .4 -> .5, .3 -> .4, etc.
    for (size_t i = config_.max_backup_files - 1; i >= 1; --i) {
        std::string src = config_.file_path + "." + std::to_string(i);
        std::string dst = config_.file_path + "." + std::to_string(i + 1);
        if (fs::exists(src, ec)) {
            fs::rename(src, dst, ec);
        }
    }

    // Rename primary file to .1
    std::string first_backup = config_.file_path + ".1";
    if (fs::exists(config_.file_path, ec)) {
        fs::rename(config_.file_path, first_backup, ec);
    }

    // Open new primary log file
    file_stream_.open(config_.file_path, std::ios::out | std::ios::trunc);
    current_file_size_ = 0;
}

std::string Logger::formatLogRecord(const LogMessage& msg) const {
    auto since_epoch = msg.timestamp.time_since_epoch();
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(since_epoch).count() % 1000000;
    std::time_t tt = std::chrono::system_clock::to_time_t(msg.timestamp);

    std::tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &tt);
#else
    localtime_r(&tt, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(6) << micros
        << " [" << levelToString(msg.level) << "] "
        << "[" << msg.file << ":" << msg.line << "] "
        << msg.content << "\n";

    return oss.str();
}

void Logger::workerLoop() {
    std::queue<LogMessage> batch;

    while (is_running_.load()) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            cv_queue_.wait(lock, [this]() {
                return !queue_.empty() || !is_running_.load();
            });

            if (!is_running_.load() && queue_.empty()) {
                break;
            }

            // Drain current queue into local batch to minimize lock contention
            batch.swap(queue_);
        }

        while (!batch.empty()) {
            const auto& msg = batch.front();
            std::string formatted = formatLogRecord(msg);

            if (config_.log_to_console) {
                // ANSI colors for console output
                const char* color_code = "\033[0m";
                switch (msg.level) {
                    case LogLevel::DEBUG:    color_code = "\033[36m"; break; // Cyan
                    case LogLevel::INFO:     color_code = "\033[32m"; break; // Green
                    case LogLevel::WARNING:  color_code = "\033[33m"; break; // Yellow
                    case LogLevel::ERROR:    color_code = "\033[31m"; break; // Red
                    case LogLevel::CRITICAL: color_code = "\033[1;31m"; break; // Bold Red
                }
                std::cout << color_code << formatted << "\033[0m";
            }

            if (file_stream_.is_open()) {
                if (current_file_size_ + formatted.size() > config_.max_file_size_bytes) {
                    rotateLogFiles();
                }
                file_stream_ << formatted;
                current_file_size_ += formatted.size();
            }

            batch.pop();
        }

        if (file_stream_.is_open()) {
            file_stream_.flush();
        }
        cv_flush_.notify_all();
    }
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:    return "DEBUG";
        case LogLevel::INFO:     return "INFO";
        case LogLevel::WARNING:  return "WARN";
        case LogLevel::ERROR:    return "ERROR";
        case LogLevel::CRITICAL: return "CRIT";
        default:                 return "UNKNOWN";
    }
}

LogLevel Logger::stringToLevel(const std::string& level_str) {
    if (level_str == "DEBUG") return LogLevel::DEBUG;
    if (level_str == "INFO") return LogLevel::INFO;
    if (level_str == "WARNING" || level_str == "WARN") return LogLevel::WARNING;
    if (level_str == "ERROR") return LogLevel::ERROR;
    if (level_str == "CRITICAL" || level_str == "CRIT") return LogLevel::CRITICAL;
    return LogLevel::INFO;
}

} // namespace firewall
