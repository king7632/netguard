#include "netguard.h"

// 静态全局变量：当前日志输出阈值（默认INFO级别）
static log_level_t current_level = LOG_INFO;


//初始化日志模块，设置输出阈值
void logger_init(log_level_t level)
{
    current_level = level;
}

//内部日志打印函数（封装核心逻辑）
static void log_print(log_level_t level, const char *tag, const char *fmt, va_list ap)
{
    // 级别过滤：仅打印≥阈值的日志（修正原逻辑：level > current_level 才过滤）
    if (level < current_level)
        return;

    // 获取当前时间并格式化（时:分:秒）
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);

    // 打印时间戳+标签
    fprintf(stdout, "[%s][%s] ", timebuf, tag);
    // 打印格式化日志内容
    vfprintf(stdout, fmt, ap);
    // 换行收尾
    fprintf(stdout, "\n");
}

/** 打印调试日志（需阈值为LOG_DEBUG才输出） */
void log_debug(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);          // 初始化可变参数列表
    log_print(LOG_DEBUG, "DEBUG", fmt, ap);
    va_end(ap);                 // 释放参数列表
}

/** 打印信息日志（阈值≥LOG_INFO时输出） */
void log_info(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_print(LOG_INFO, "INFO", fmt, ap);
    va_end(ap);
}

/** 打印告警日志（所有阈值下均输出） */
void log_alert(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_print(LOG_ALERT, "ALERT", fmt, ap);
    va_end(ap);
}