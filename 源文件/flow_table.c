#include"netguard.h"

// 静态数组：存储所有源IP的TCP流统计记录（仅当前文件可见，实现封装）
// 一个元素对应一个源IP的全维度行为统计
static tcp_flow_t flow_table[MAX_FLOWS];
// 静态变量：记录当前已跟踪的流数量（即已统计的不同源IP数），初始为0
static int flow_count = 0;

//初始化TCP流表
void flow_table_init(void)
{
    // 将flow_table数组的所有内存置0（初始化所有tcp_flow_t字段为默认值）
    memset(flow_table, 0, sizeof(flow_table));
    flow_count = 0; // 重置已跟踪的流数量为0
}

//检查目标端口是否已存在于当前流的端口列表中（去重）
static int port_exists(tcp_flow_t *flow, uint16_t port)
{
    // 遍历已记录的唯一端口列表，匹配目标端口
    for (int i = 0; i < flow->unique_ports; i++)
        if (flow->ports[i] == port)
            return 1; // 端口已存在，返回1
    return 0; // 端口未存在，返回0
}


//根据源IP获取/创建TCP流记录
tcp_flow_t *flow_get(uint32_t src_ip)
{
    // 第一步：遍历已存在的流表，查找该源IP的记录
    for (int i = 0; i < flow_count; i++) {
        if (flow_table[i].src_ip == src_ip)
            return &flow_table[i]; // 找到，返回该IP的流记录指针
    }

    // 第二步：未找到则检查流表是否已满，避免数组越界
    if (flow_count >= MAX_FLOWS)
        return NULL;

    // 第三步：创建新的流记录
    tcp_flow_t *flow = &flow_table[flow_count++]; // 取数组下一个空闲位置，流计数+1
    memset(flow, 0, sizeof(*flow));               // 初始化新记录的所有字段为0
    flow->src_ip = src_ip;                        // 绑定源IP（流的唯一标识）
    flow->first_seen = time(NULL);                // 记录该IP首次出现的时间戳
    flow->last_seen  = flow->first_seen;          // 首次出现时，末次时间戳与首次一致

    log_info("New flow created for src=%s", inet_ntoa(*(struct in_addr *)&src_ip));
    flow->syn_flood_alerted=0;
    flow->port_scan_alerted=0;
    flow->rst_storm_alerted=0;
    flow->malformed_alerted=0;

    return flow;
}

//核心函数：更新单个IP的TCP流统计数据
void flow_update(tcp_flow_t *flow,
                 uint16_t dst_port,
                 uint8_t flags)
{
    // 1. 更新该IP末次出现的时间戳（每次收到包都刷新）
    time_t now = time(NULL);
    flow->last_seen = now;

    // 2. 统计各类TCP标志位的出现次数（按位与判断标志位是否置1）
    if (flags & 0x02) flow->syn_count++;    
    if (flags & 0x10) flow->ack_count++;    
    if (flags & 0x04) flow->rst_count++;   

    // 3. 统计异常标志位组合：SYN+FIN（0x02|0x01）——正常TCP不会出现该组合，属于异常
    if ((flags & 0x02) && (flags & 0x01))
        flow->abnormal_flag_count++; // SYN+FIN组合，异常计数+1

    // 只统计主动探测端口：SYN 且非 ACK
    if ((flags & TH_SYN) && !(flags & TH_ACK)) 
    {
      if (!port_exists(flow, dst_port) && flow->unique_ports < MAX_PORTS) 
      {
        flow->ports[flow->unique_ports++] = dst_port;
      }
    }

    /* 5. 每次更新完统计数据后，触发全维度异常检测 */
    detect_all(flow);
}