#include "netguard.h"

/* ========= 可调阈值 ========= */
#define SYN_FLOOD_SYN_THRESHOLD     25  // SYN Flood触发阈值：SYN包数量
#define SYN_FLOOD_TIME_WINDOW       3    // SYN Flood检测时间窗口，单位秒
#define PORT_SCAN_PORT_THRESHOLD    20   // 端口扫描触发阈值：唯一端口数
#define PORT_SCAN_TIME_WINDOW       2    // 端口扫描检测时间窗口，单位秒
#define RST_STORM_THRESHOLD         50   // RST风暴触发阈值：RST包数量
#define RST_STORM_TIME_WINDOW       3    // RST风暴检测时间窗口，单位秒
#define ALERT_COOLDOWN              5    // 告警冷却：IP沉寂超此时长重置统计

/* ========= 内部工具函数 ========= */
// 重置流统计：时间戳、各类计数、端口列表全部清零
static void reset_flow_stats(tcp_flow_t *flow, time_t now)
{
    flow->first_seen = now;      // 重置首次出现时间为当前
    flow->last_seen  = now;      // 重置末次出现时间为当前
    flow->syn_count  = 0;        // 重置SYN包计数
    flow->ack_count  = 0;        // 重置ACK包计数
    flow->rst_count  = 0;        // 重置RST包计数
    flow->unique_ports = 0;      // 重置唯一端口数
    memset(flow->ports, 0, sizeof(flow->ports)); // 清空端口列表
    flow->abnormal_flag_count = 0; // 重置畸形标志位计数
}

/* ========= 内部检测函数声明 ========= */
static void detect_syn_flood(tcp_flow_t *flow);    // 检测SYN洪水攻击
static void detect_port_scan(tcp_flow_t *flow);    // 检测TCP端口扫描行为
static void detect_rst_storm(tcp_flow_t *flow);    // 检测RST包风暴攻击
static void detect_abnormal_flags(tcp_flow_t *flow);// 检测畸形TCP标志位攻击

/* ========= 统一检测入口 ========= */
// 全量异常检测入口：先冷却判断，再执行各类检测
void detect_all(tcp_flow_t *flow)
{
    if (!flow) return; // 空指针防护

    time_t now = time(NULL); // 获取当前时间戳

    /* 全局冷却逻辑：
     * 如果这个 IP 已经“沉寂”了一段时间，
     * 就认为是新一轮行为，重置统计
     */
    if (now - flow->last_seen >= ALERT_COOLDOWN) {
        reset_flow_stats(flow, now); // 超冷却时间，重置统计
        return;
    }

    // 依次执行各类异常检测
    detect_syn_flood(flow);
    detect_port_scan(flow);
    detect_rst_storm(flow);
    detect_abnormal_flags(flow);
}

/* ========= 1. SYN Flood ========= */
// SYN Flood检测：时间窗口内SYN包超阈值则告警并重置
static void detect_syn_flood(tcp_flow_t *flow)
{
    time_t duration = flow->last_seen - flow->first_seen; // 计算活动时长
    if (duration <= 0 || duration > SYN_FLOOD_TIME_WINDOW)
        return; // 时长异常/超窗口，不检测

    if (flow->syn_count >= SYN_FLOOD_SYN_THRESHOLD) // 达到SYN包阈值
    {
        struct in_addr addr;
        addr.s_addr = flow->src_ip; // 转换IP格式

        // 输出SYN Flood告警
        log_alert(
            "\nSYN_FLOOD src=%s syn=%d duration=%lds\n",
            inet_ntoa(addr),
            flow->syn_count,
            duration
        );

        reset_flow_stats(flow, time(NULL)); // 告警后重置，避免重复刷屏
    }
}

/* ========= 2. 端口扫描 ========= */
// 端口扫描检测：时间窗口内唯一端口数超阈值则告警并重置
static void detect_port_scan(tcp_flow_t *flow)
{
    time_t duration = flow->last_seen - flow->first_seen; // 活动时长
    if (duration <= 0 || duration > PORT_SCAN_TIME_WINDOW)
        return; // 时长异常/超窗口，不检测

    if (flow->unique_ports >= PORT_SCAN_PORT_THRESHOLD) // 达到端口数阈值
    {
        struct in_addr addr;
        addr.s_addr = flow->src_ip; // 转换IP格式

        // 输出端口扫描告警
        log_alert(
            "\nPORT_SCAN src=%s ports=%d duration=%lds\n",
            inet_ntoa(addr),
            flow->unique_ports,
            duration
        );

        reset_flow_stats(flow, time(NULL)); // 告警后重置统计
    }
}

/* ========= 3. RST 风暴 ========= */
// RST风暴检测：时间窗口内RST包超阈值则告警并重置
static void detect_rst_storm(tcp_flow_t *flow)
{
    time_t duration = flow->last_seen - flow->first_seen; // 活动时长
    if (duration <= 0 || duration > RST_STORM_TIME_WINDOW)
        return; // 时长异常/超窗口，不检测

    if (flow->rst_count >= RST_STORM_THRESHOLD) // 达到RST包阈值
    {
        struct in_addr addr;
        addr.s_addr = flow->src_ip; // 转换IP格式

        // 输出RST风暴告警
        log_alert(
            "\nRST_STORM src=%s rst=%d duration=%lds\n",
            inet_ntoa(addr),
            flow->rst_count,
            duration
        );

        reset_flow_stats(flow, time(NULL)); // 告警后重置统计
    }
}

/* ========= 4. 畸形 TCP Flag ========= */
// 畸形标志位检测：存在异常标志位则告警并重置
static void detect_abnormal_flags(tcp_flow_t *flow)
{
    if (flow->abnormal_flag_count > 0) // 存在畸形标志位计数
    {
        struct in_addr addr;
        addr.s_addr = flow->src_ip; // 转换IP格式

        // 输出畸形TCP包告警
        log_alert(
            "\nMALFORMED_TCP src=%s abnormal_flags=%d\n",
            inet_ntoa(addr),
            flow->abnormal_flag_count
        );

        reset_flow_stats(flow, time(NULL)); // 告警后重置统计
    }
}