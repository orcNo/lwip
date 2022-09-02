#ifndef _PROXY_IP_H
#define _PROXY_IP_H

#ifndef SHANDLE
#define SHANDLE void*
#endif

#ifndef MAKE_DST
#define MAKE_DST(addr, port) ((((uint64_t)addr) << 16) | (port))
#endif

#include <stdint.h>

extern int g_sock;

enum IPacketType {
    IPT_ICMP = 1,
    IPT_TCP = 6,
    IPT_UDP = 17
};

#pragma pack(push, 1)
typedef __declspec(align(2)) struct _stTcpData {
    enum IPacketType type;
    uint8_t* data;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t ident;
} TcpData;

__declspec(align(2)) struct _stDataList {
    uint16_t* idens;
    TcpData* datas;
    uint16_t len;
    uint16_t curs;
};
typedef struct _stDataList DataList;

typedef __declspec(align(4)) struct _stConn {
    uint64_t dst;
    SHANDLE conn;
    uint32_t la; /*last active time*/
} Conn;

typedef __declspec(align(2)) struct _stConnList {
    uint16_t len;
    uint16_t curs;
    Conn* data;
} ConnList;

#pragma pack(pop)
extern DataList* g_list;
extern uint32_t tcp_socks_addr[4];
extern uint16_t tcp_socks_port;

extern uint32_t udp_socks_addr[4];
extern uint16_t udp_socks_port;

struct pbuf;
struct netif;
int gen_user_packet(struct pbuf* p, struct netif *netif);
void gen_ip_packet(void* src, uint32_t slen, void* out, uint32_t *olen, TcpData* td);
void check_ip_head(struct pbuf* pbuf);
void check_tcp(struct pbuf* pbuf);
void print_pbuf(struct pbuf* p);
void free_data_list(void);

void send_packet(void *d);

#endif /** _PROXY_IP_H */
