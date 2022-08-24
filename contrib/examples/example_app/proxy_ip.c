
/*#include "lwip/sockets.h"*/
#include <pcap.h>

#include "netif/etharp.h"
#include "lwip/sys.h"

#include "proxy_ip.h"

#include <client.h>

#include <string.h>
#include <stdio.h>
#include <assert.h>

#define IP_HEADER_OFFSET_WORD 0
#define IP_HEADER_IDEN_DWORD 2
#define IP_HEADER_FLAG_WORD 6

#define GET_IP_HEADER_PTR(p) ((unsigned char*)p + IP_HEADER_OFFSET_WORD)
#define GET_IP_HLEN(ip) ((*(unsigned char*)(ip) & 0xF) * 4)
#define GET_IP_TLEN(ip) (((unsigned char*)(ip))[2] << 8 | ((unsigned char*)(ip))[3])
#define GET_IP_IDEN(ip) (((unsigned char*)(ip))[4] << 8 | ((unsigned char*)(ip))[5])
#define GET_IP_FLAG(ip) (((unsigned char*)(ip))[IP_HEADER_FLAG_WORD] >> 5)
#define GET_IP_FOFFSET(ip) (((uint16_t*)(void*)(ip))[3] & 0x1FFF)
#define GET_IP_SADDR(ip) (*((uint32_t*)(void*)(ip) + 3))
#define GET_IP_DADDR(ip) (*((uint32_t*)(void*)(ip) + 4))
#define GET_IP_TYPE(ip) (((unsigned char*)(void*)(ip))[9])

#define GET_TCP_HEADER_PTR(ip) (unsigned char*)(void*)(ip) + (GET_IP_TLEN(ip) - GET_IP_HLEN(ip))
#define GET_TCP_SPORT(tcp)  *(uint16_t*)(void*)(ip)
#define GET_TCP_DPORT(tcp)  *((uint16_t*)(void*)ip + 1)

#ifndef UNUSED
#define UNUSED(x) (void)x;
#endif

#define LWIPCAP_DEBUG 1

#if LWIPCAP_DEBUG
#ifndef DEBUG_PRINT
#define DEBUG_PRINT printf
#endif
#endif

#define DEALUT_LIST_SIZE 8

struct pcapif_private {
    void* input_fn_arg;
    pcap_t* adapter;
};

/*DataList g_stList;*/
DataList* g_list = NULL;
ConnList* g_connList = NULL;

/*extern struct netif* g_netif;*/
extern pcap_t* g_adapter;

int g_socket = 0;

uint32_t tcp_socks_addr[4];
uint16_t tcp_socks_port;

uint32_t udp_socks_addr[4];
uint16_t udp_socks_port;

static TcpData* list_new_data(void);

typedef struct _stIpHeader {
    unsigned char vhl; /*version[4bits] & hlen[4bits]*/
    unsigned char service_type;
    uint16_t total_len;
    uint16_t ident;
    uint16_t ffoff;/* flags[3bits] & fragmentation offset[13bit]*/
    unsigned char ttl; /*time to live*/
    unsigned char prot; /**/
    unsigned char checksum;
    uint32_t saddr;
    uint32_t daddr;
} Ipv4Header;

static void clean_TcpData(TcpData* td) {
    if (!td)
        return;
    /*DEBUG_PRINT("free td->data: %ld.\n", td->data);*/
    mem_free(td->data);
    td->data = NULL;
}

static TcpData* get_data(int iden) {
    int i = 0;

    if (!g_list) {
        g_list = (DataList *)mem_malloc(sizeof(struct _stDataList));
        memset(g_list, 0, sizeof(DataList));

        return NULL;
    }

    for (; i < g_list->curs; ++i) {
        if (g_list->datas[i].ident == iden) {
            return g_list->datas + i;
        }
    }

    return NULL;
}

static TcpData* list_new_data(void) {
    if (g_list->len == g_list->curs) {
        uint16_t oldlen = g_list->len;
        TcpData* oldd = g_list->datas;
        uint16_t* oldident = g_list->idens;
        g_list->len = g_list->len ? g_list->len << 1 : DEALUT_LIST_SIZE;
        g_list->datas = (TcpData*)mem_malloc(sizeof(TcpData) * g_list->len);
        g_list->idens = (uint16_t*)mem_malloc(sizeof(unsigned short) * g_list->len);

        if (oldlen) {
            memcpy(g_list->datas, oldd, sizeof(TcpData) * oldlen);
            memcpy(g_list->idens, oldident, sizeof(unsigned short) * oldlen);
            mem_free(oldd);
            mem_free(oldident);
        }
    }

    return g_list->datas + (g_list->curs++);
}

void free_data_list(void) {
    if (!g_list)
        return;
    mem_free(g_list->datas);
    mem_free(g_list->idens);
    mem_free(g_list);
}

static TcpData* dump_packet_data(TcpData* src) {
    TcpData* ptd = (TcpData*)mem_malloc(sizeof(TcpData));
    DEBUG_PRINT(">>>>> mem_malloc td: %p.\n", (void*)ptd);
    memcpy(ptd, src, sizeof(TcpData));

    ptd->data = (unsigned char*)mem_malloc(sizeof(unsigned char) * src->len);
    /*DEBUG_PRINT("mem_malloc td->data: %p.\n", (void*)ptd->data);*/
    memcpy(ptd->data, src->data, sizeof(unsigned char) * src->len);

    return ptd;
}

static int remove_data(TcpData* td) {
    int off = (td - g_list->datas);
    if (off > g_list->len || off < 0)
        return -1;
    clean_TcpData(td);
    memcpy(td, td + 1, sizeof(TcpData) * (g_list->curs - off));
    /*mem_free(td);*/
    td = NULL;
    g_list->curs--;

    return 0;
}
#if 0
static int take_data(TcpData* td) {
    TcpData* tp = NULL;
    int off = (td - g_list->datas);

    if (off > g_list->len || off < 0) {
        return -1;
    }

    tp = (TcpData*)mem_malloc(sizeof(TcpData));
    memcpy(tp, td, sizeof(TcpData));
    memcpy(g_list->datas, td + 1, sizeof(TcpData) * (g_list->len - off));
    td = NULL;
    g_list->curs--;

    return 0;
}
#endif
int gen_user_packet(struct pbuf* p, struct netif *netif)
{
    unsigned char* ip = GET_IP_HEADER_PTR(p->payload);
    unsigned char ip_hlen = GET_IP_HLEN(ip);
    uint16_t ip_tlen = GET_IP_TLEN(ip);
    uint16_t tcp_tlen = ip_tlen - ip_hlen;
    uint16_t iden = GET_IP_IDEN(ip);
    unsigned char flag = GET_IP_FLAG(ip);
    uint16_t foffset = GET_IP_FOFFSET(ip);
    uint8_t type = GET_IP_TYPE(ip);

    unsigned char* tcp = GET_TCP_HEADER_PTR(ip);
    /** unsigned char tcp_hlen = tcp[12] >> 12; */
    /**uint16_t tcp_tlen = tcp_tlen - tcp_hlen; */
    uint16_t tcp_dlen = p->len - IP_HEADER_OFFSET_WORD - ip_hlen;
    /** unsigned char* dtcp = tcp + tcp_hlen; */
    TcpData* ptd;
    TcpData* ttd;

    UNUSED(netif);

    if (type != IPT_ICMP && type != IPT_UDP && type != IPT_TCP)
        return 0;

    print_pbuf(p);
    fflush(stdout);
    if (flag == 0x2) {
        char th_name[1024];
        /**包未拆分 */
        ptd = (TcpData*)malloc(sizeof(TcpData));
        DEBUG_PRINT(">>>>>> malloc td: %p.\n", (void*)ptd);
        ptd->saddr = (uint32_t)GET_IP_SADDR(ip);
        ptd->daddr = GET_IP_DADDR(ip);
        ptd->sport = GET_TCP_SPORT(tcp);
        ptd->dport = GET_TCP_DPORT(tcp);
        ptd->ident = iden;
        ptd->type = (enum IPacketType)type;
        ptd->len = tcp_tlen;
        ptd->data = (unsigned char*)mem_malloc(sizeof(unsigned char) * tcp_tlen);
        assert(ptd->data);
        memcpy(ptd->data, tcp, sizeof(unsigned char) * tcp_dlen);

        DEBUG_PRINT("call send_packet %d with flag 0x2.\n", ptd->ident);
        sprintf(th_name, "send_packet_%d", ptd->ident);
        sys_thread_new(th_name, send_packet, ptd, 512, 4);
        return 1;
    }

    /**组包 */
    ttd = get_data(iden);
    if (!ttd) {
        ttd = list_new_data();
        ttd->saddr = GET_IP_SADDR(ip);
        ttd->daddr = GET_IP_DADDR(ip);
        ttd->sport = GET_TCP_SPORT(tcp);
        ttd->dport = GET_TCP_DPORT(tcp);
        ttd->ident = iden;
        ttd->len = tcp_tlen;
        ttd->type = (enum IPacketType)type;
        ttd->data = (unsigned char*)mem_malloc(sizeof(char) * tcp_tlen);
        /*DEBUG_PRINT("malloc tmp data: %p.\n", (void*)ttd->data);*/
    }
    assert(ttd->data);
    memcpy(ttd->data + foffset, tcp, sizeof(char) * tcp_dlen);

    if (flag == 0x0) {
        char th_name[1024];
        ptd = dump_packet_data(ttd);
        DEBUG_PRINT("call send_packet %d with flag 0x0.\n", ptd->ident);
        sprintf(th_name, "send_packet_%d", ptd->ident);
        sys_thread_new(th_name, send_packet, ptd, 512, 4);
        remove_data(ttd);
    }
    return 1;
}

void print_pbuf(struct pbuf* p) {
    unsigned char* buf = (unsigned char*)p->payload;
    int idx = 0;

    if (p->len == 0) {
        return;
    }
    DEBUG_PRINT("--------------: \n\t");

    for (; idx < p->len; ++idx) {
        DEBUG_PRINT("%2x ", buf[idx]);
        if ((idx + 1) % 8 == 0) {
            if ((idx + 1) % 16 == 0) {
                DEBUG_PRINT("\n\t");
                continue;
            }
            DEBUG_PRINT(" ");
        }
    }
    DEBUG_PRINT("\n");
}

#define IP_HEADER_OFFSET 14 /**byte */

void check_tcp(struct pbuf* pbuf) {
    uint16_t res = 0;
    /**uint16_t* ip_header; */
    uint16_t* buf;
    uint32_t sum = 0;
    int idx = 0;

    uint16_t* p = (uint16_t*)pbuf->payload + IP_HEADER_OFFSET / 2;
    int ip_header_len = 4 * (*p & 0xF >> 4) / 2;
    int tcp_len = p[1] / 2 - ip_header_len;

    /**伪头部 */
    buf = (uint16_t*)mem_malloc(sizeof(uint16_t) * (tcp_len + 6));
    buf[0] = p[6];
    buf[1] = p[7];
    buf[2] = p[8];
    buf[3] = p[9];
    buf[4] = 6;/** protocol, tcp: 6, udp: 17 */
    buf[5] = tcp_len;/** tcp length */

    memcpy(buf + 6, p + ip_header_len, sizeof(uint16_t) * tcp_len);

    res = buf[14];
    buf[14] = 0;
    sum = (~buf[0] & 0xFFFF);

    for (idx = 1; idx < tcp_len + 6; ++idx) {
        sum += (~buf[idx] & 0xFFFF);
    }
    while (sum & 0xFFFF0000) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    if (sum != res) {
        DEBUG_PRINT("error package!");
    }
    mem_free(buf);
}

void check_ip_head(struct pbuf* pbuf) {
    uint32_t sum = 0;
    int idx = 0;
    /**int len = (pbuf->len - 14)/2; */
    int len = 10;
    uint16_t res = 0;
    uint16_t* buf;

    buf = (uint16_t*)mem_malloc(sizeof(uint16_t) * len);

    memcpy(buf, (uint16_t*)pbuf->payload + 7, sizeof(uint16_t) * len);
    if (len <= 0)
        return;

    sum = (~buf[0] & 0xFFFF);
    res = buf[5];
    buf[5] = 0;

    for (idx = 1; idx < len; ++idx) {
        sum += (~buf[idx] & 0xFFFF);
    }
    while (sum & 0xFFFF0000) {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    if (sum != res) {
        DEBUG_PRINT("error package!");
    }
    mem_free(buf);
}


static SHANDLE find_conn(uint32_t addr, uint16_t port) {
    uint64_t dst = MAKE_DST(addr, port);
    uint32_t idx = 0;

    if (!g_connList)
        return NULL;

    for (; idx < g_connList->curs; ++idx) {
        if (dst == g_connList->data[idx].dst) {
            break;
        }
    }
    if (idx != g_connList->curs) {
        return g_connList->data[idx].conn;
    }

    return NULL;
}

static void add_conn(SHANDLE h, uint32_t addr, uint16_t port) {
    UNUSED(h)
    if (!g_connList) {
        g_connList = (ConnList*)malloc(sizeof(ConnList));
        memset(g_connList, 0, sizeof(ConnList));
    }

    /*如果明确用户操作，这里的查找可以省掉*/
    if (find_conn(addr, port))
        return;

    if (g_connList->curs == g_connList->len) {
        uint16_t oldlen = g_connList->len;
        Conn* olddata = (Conn*)g_connList->data;
        g_connList->len = oldlen ? g_connList->len << 2 : DEALUT_LIST_SIZE;
        g_connList->data = (Conn*)malloc(sizeof(SHANDLE) * g_connList->len);
        if (oldlen) {
            memcpy(g_connList->data, olddata, sizeof(SHANDLE));
        }
    }
}

void send_packet(void *d) {
    int err = 0;
    int close_conn = 1;
    SHANDLE h = NULL;
    TcpData* td = (TcpData*)d;
    if (!td || !td->data)
        return;

    switch (td->type) {
    case IPT_ICMP:
        break;
    case IPT_TCP: {
        h = find_conn(td->daddr, td->dport);
        if (!h) {
            uint32_t daddr[4] = { 0 };
            daddr[3] = td->daddr;
            h = sclient_connect(tcp_socks_addr, tcp_socks_port, daddr, td->dport);
            if (!h) {
                /*error*/
                err = -2;
                goto end;
            }
            add_conn(h, td->daddr, td->dport);
        }
        sclient_send(h, (const char*)td->data, td->len);
        DEBUG_PRINT("send tcp data.\n");
    }        
        break;
    case IPT_UDP: {
        char* buf;
        
        h = find_conn(td->daddr, td->dport);
        close_conn = 0;
        if (!h) {
            uint32_t daddr[4] = { 0 };
            daddr[3] = td->daddr;
            h = sclient_connect(udp_socks_addr, udp_socks_port, daddr, td->dport);
            if (!h) {
                /*error*/
                err = -2;
                goto end;
            }
            add_conn(h, td->daddr, td->dport);
        }
        buf = (char*)mem_malloc(sizeof(char) * (td->len + 1 + 8));
        buf[0] = 0x4;
        *(uint32_t*)(void*)(buf + 1) = td->saddr;
        *(uint32_t*)(void*)(buf + 5) = td->daddr;
        memcpy(buf + 9, td->data, td->len);
        sclient_send(h, buf, td->len + 1 + 8);
        mem_free(buf);
        DEBUG_PRINT("send udp data.\n");
    }
        break;
    default:
        break;
    }

    err = 0;
    if (err == 0 && h) {
        char recv_buf[1024];
        unsigned int recv_len = 0;
        /*struct pcapif_private* pa = (struct pcapif_private*)(g_netif)->state;*/
        /*sclient_set_time*/
        while ((recv_len = sclient_recv(h, recv_buf, 1024)) > 0) {
            /**/
            char ipbuf[2049];
            unsigned int iplen;
            gen_ip_packet((void*)recv_buf, recv_len, ipbuf, &iplen, td);
            if (g_adapter) {
                /*TODO*/
                /*pcap_sendpacket(g_adapter, recv_buf, recv_len);*/
            }
        }
        if (close_conn)
            sclient_close(h);
    }

end:
    clean_TcpData(td);
    DEBUG_PRINT("<<<<<< mem_free td: %p.\n", (void*)td);
    mem_free(td);
    td = NULL;
}

void gen_ip_packet(void* data, uint32_t dlen, void* packet,uint32_t* plen, TcpData* td) {
    Ipv4Header iph;
    iph.vhl = 0x4 << 4 | 0x5;
    iph.service_type = 0x0;
    iph.total_len = htons(dlen / 4 + 0x5);
    iph.ident = td->ident;
    iph.ffoff = 0x0;
    iph.ttl = 0x40;
    iph.prot = td->type;
    iph.checksum = 0;/* check_ip_head(NULL); //TODO*/
    iph.saddr = td->saddr;
    iph.daddr = td->daddr;
    
    UNUSED(iph);
    UNUSED(data);
    UNUSED(packet);
    UNUSED(plen);
    UNUSED(td);
    UNUSED(iph);
}
