#include"netguard.h"

int parse_tcp_packet(const unsigned char *packet,
                     size_t len,
                     tcp_info_t *info)
{
    if (len < sizeof(struct ip))
        return 0;

    const struct ip *ip_hdr = (const struct ip *)packet;

    if (ip_hdr->ip_p != IPPROTO_TCP)
        return 0;

    int ip_header_len = ip_hdr->ip_hl * 4;
    if (len < ip_header_len + sizeof(struct tcphdr))
        return 0;

    const struct tcphdr *tcp_hdr =
        (const struct tcphdr *)(packet + ip_header_len);

    memset(info, 0, sizeof(*info));

    info->src_ip   = ip_hdr->ip_src.s_addr;
    info->dst_ip   = ip_hdr->ip_dst.s_addr;
    info->src_port = ntohs(tcp_hdr->th_sport);
    info->dst_port = ntohs(tcp_hdr->th_dport);
    info->flags    = tcp_hdr->th_flags;

    // 定义存储IP地址字符串的数组
    char src_ip[INET_ADDRSTRLEN];  // 存储源IP地址的字符串形式（如"127.0.0.1"）
    char dst_ip[INET_ADDRSTRLEN];  // 存储目的IP地址的字符串形式

    // 将IP头部中的二进制源IP地址（网络字节序）转换为点分十进制的字符串格式
    inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, sizeof(src_ip));
    // 将二进制目的IP地址转换为点分十进制的字符串格式
    inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, sizeof(dst_ip));
    
    log_debug(
    "TCP %s:%d -> %s:%d FLAGS:%s%s%s%s",
    src_ip,
    info->src_port,
    dst_ip,
    info->dst_port,
    (info->flags & TH_SYN) ? " SYN" : "",
    (info->flags & TH_ACK) ? " ACK" : "",
    (info->flags & TH_FIN) ? " FIN" : "",
    (info->flags & TH_RST) ? " RST" : ""
    );

    return 1;
}