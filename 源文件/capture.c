#include "netguard.h"

//数据包回调处理函数
static void packet_handler(
    unsigned char *user,
    const struct pcap_pkthdr *header,
    const unsigned char *packet)
{
    // 将原始数据包指针强制转换为以太网头部结构体指针，解析链路层头部
    const struct ether_header *eth =
        (const struct ether_header *)packet;

    // 检查以太网帧类型：仅处理IP协议数据包
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;

    // 定义tcp_info_t结构体变量，用于存储解析后的TCP数据包信息
    tcp_info_t info;

    // 调用自定义TCP数据包解析函数并更新状态
    if (parse_tcp_packet(
        packet + sizeof(struct ether_header),
        header->caplen - sizeof(struct ether_header),
        &info
    ))
    {
        tcp_flow_t *flow = flow_get(info.src_ip);
        if (!flow) return;
        flow_update(flow, info.dst_port, info.flags);
    }


}

//启动网络抓包功能
void start_capture(const char *dev)
{
    // 定义错误缓冲区，存储libpcap函数调用失败时的错误信息（固定大小PCAP_ERRBUF_SIZE）
    char errbuf[PCAP_ERRBUF_SIZE];
    // 定义pcap句柄指针，指向抓包会话的上下文，后续抓包操作依赖此句柄
    pcap_t *handle;

    // 打开指定网络接口进行实时抓包
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    // 检查抓包句柄是否创建成功
    if (!handle) {
        // 失败则打印错误信息到标准错误输出
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        // 退出程序，错误码1表示异常退出
        exit(1);
    }

    // 无限循环捕获数据包，直到出错或手动终止（-1表示捕获无限个数据包）
    pcap_loop(handle, -1, packet_handler, NULL);
    // 关闭抓包句柄，释放系统资源（仅当pcap_loop退出时执行）
    pcap_close(handle);
}