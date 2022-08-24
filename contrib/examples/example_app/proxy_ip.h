#ifndef _PROXY_IP_H
#define _PROXY_IP_H

#include "socks5.h"
#ifndef SHANDLE
#define SHANDLE void*
#endif

#ifndef MAKE_DST
#define MAKE_DST(addr, port) ((((uint64_t)addr) << 16) | (port))
#endif

typedef struct _stDataList {
    uint16_t len;
    uint16_t curs;
    uint16_t* idens;
    TcpData* datas;
} DataList;

typedef struct stConn {
    uint64_t dst;
    uint32_t la; /*last active time*/
    SHANDLE conn;
} Conn;

typedef struct _stConnList {
    uint16_t len;
    uint16_t curs;
    Conn* data;
} ConnList;

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
