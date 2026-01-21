#include <pcap.h>          // 抓包库工具箱
#include <stdio.h>         // 打印工具箱
#include <time.h>          // 时间相关
#include <netinet/in.h>    // IP地址转换
#include <arpa/inet.h>     // IP地址转换
#include <errno.h>         // 错误码
#include <string.h>        // 字符串操作
#include <stdint.h>        // 固定长度整型
#include <stddef.h>        // 标准类型/NULL/偏移
#include <netinet/tcp.h>   // TCP头部结构体
#include <netinet/ip.h>    // IP头部结构体
#include <net/ethernet.h>  // 以太网头部结构体
#include <stdlib.h>        // 内存/进程管理
#include <stdarg.h>        // 处理可变参数

// TCP 信息结构体
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  flags;   // SYN / ACK / FIN 等
} tcp_info_t;

// 返回 1 表示是 TCP 包，0 表示不是
int parse_tcp_packet(const unsigned char *packet,
                     size_t len,
                     tcp_info_t *info);

//抓包函数
void start_capture(const char *dev);

#define MAX_FLOWS 1024
#define MAX_PORTS 256

// 定义TCP流统计结构体：用于跟踪单个源IP的全维度TCP行为特征，支撑异常流量检测
// 一个tcp_flow_t对应一个源IP，记录该IP的所有TCP交互行为
typedef struct {
    uint32_t src_ip;                // 源IP地址（网络字节序），作为该流的唯一标识
    int syn_count;                  // 该IP发送的SYN标志包累计数量（含纯SYN、SYN+ACK等）
    int ack_count;                  // 该IP发送的ACK标志包累计数量
    int rst_count;                  // 该IP发送的RST标志包累计数量
    
    int abnormal_flag_count;        // 该IP发送的异常标志位组合包累计数
    
    uint16_t ports[MAX_PORTS];      // 该IP访问过的目的端口列表（去重），MAX_PORTS为端口列表最大容量
    int unique_ports;               // 该IP访问过的唯一目的端口数量（ports数组的有效元素数）
    
    time_t first_seen;              // 该IP首次出现的时间戳（记录攻击/异常行为的起始时间）
    time_t last_seen;               // 该IP末次出现的时间戳（记录行为的最新时间，用于过期清理）
    time_t last_alert_time;

    int syn_flood_alerted;
    int port_scan_alerted;
    int rst_storm_alerted;
    int malformed_alerted;

} tcp_flow_t;

//初始化TCP流表（核心初始化函数）
void flow_table_init(void);

//根据源IP获取已存在的TCP流记录，若不存在则创建新记录
tcp_flow_t *flow_get(uint32_t src_ip);


//核心更新函数：根据单个TCP数据包的信息，更新对应IP的flow统计数据
void flow_update(tcp_flow_t *flow,
                 uint16_t dst_port,
                 uint8_t tcp_flags);

//异常检测模块
void detect_all(tcp_flow_t *flow);

// 日志级别枚举：控制输出粒度
typedef enum {
    LOG_DEBUG = 0,  // 调试级：开发调试细节
    LOG_INFO  = 1,  // 信息级：正常流程信息
    LOG_ALERT = 2   // 告警级：攻击/异常告警
} log_level_t;

//初始化日志模块
void logger_init(log_level_t level);

/** 打印调试日志（仅阈值为LOG_DEBUG时输出） */
void log_debug(const char *fmt, ...);

/** 打印信息日志（阈值≥LOG_INFO时输出） */
void log_info(const char *fmt, ...);

/** 打印告警日志（所有阈值下均输出） */
void log_alert(const char *fmt, ...);
