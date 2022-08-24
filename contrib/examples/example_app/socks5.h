#ifndef _SOCKS5_H
#define _SOCKS5_H


#if defined(__GNUC__) || defined(__GNUG__)
#include <stdint.h>
#elif define(_MSC_VER)
#ifndef uint8_t
#define uint8_t unsigned __int8
#endif
#ifndef uint16_t 
#define uint16_t uint16_t
#endif
#ifndef uint32_t
#define uint32_t unsigned ___int32
#endif
#ifndef uint64_t
#define uint64_t unsigned ___int64
#endif

#ifndef int8_t
#define int8_t __int8
#endif
#ifndef int16_t 
#define int16_t __int16 
#endif
#ifndef int32_t
#define int32_t __int32
#endif
#ifndef int64_t
#define int64_t __int64
#endif
#endif /*__unix*/

extern int g_sock;

enum IPacketType {
    IPT_ICMP = 1,
    IPT_TCP = 6,
    IPT_UDP = 17
};

typedef struct _stTcpData {
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t ident;
    enum IPacketType type;
    unsigned char* data;
} TcpData;

#endif
