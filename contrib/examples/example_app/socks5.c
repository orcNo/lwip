#include "socks5.h"
#include "proxy_ip.h"

#include "lwip/opt.h"

#include "lwip/sys.h"
#include "lwip/api.h"

#include <lwip/sockets.h>

#define PORT              10808
#define IP_ADDR        "127.0.0.1"

int g_sock = -1;

void send_tcp(TcpData* td) {

}

struct Ipv4Address
{
    union
    {
        uint32_t    addr;
        uint8_t     parts[4];
        struct
        {
            uint8_t   part4;
            uint8_t   part3;
            uint8_t   part2;
            uint8_t   part1;
        };
    };
    uint16_t      port;
};

struct Ipv4Address Ipv4(uint8_t p1, uint8_t p2, uint8_t p3, uint8_t p4, uint16_t _port)
{
    struct Ipv4Address a = {0};
    a.part1 = p1;
    a.part2 = p2;
    a.part3 = p3;
    a.part4 = p4;
    a.port = _port;
    return a;
}

static void client(void* thread_param)
{
    int sock = -1;
    struct sockaddr_in client_addr;

    unsigned char send_buf[] = "This is a TCP Client test...\n";

    while (1)
    {
        //const WORD requested_version = MAKEWORD(2, 2);
        //WSADATA wsa_data = {0};
        //int err = WSAStartup(requested_version, &wsa_data);
        //if (err != 0)
        //    printf("Socket error: %d\n", err);
        //if (wsa_data.wVersion != requested_version) {
        //    WSACleanup();
        //    printf("Socket error\n");
        ////}
        //int  BUF_SIZE = 200000;
        //tcpip_init(NULL, NULL);
        /* DHCP */
        //enum { BUF_SIZE = Nic::Packet_allocator::DEFAULT_PACKET_SIZE * 128 };
        //if (lwip_nic_init(0, 0, 0, BUF_SIZE, BUF_SIZE)) {
        //    printf("ERROR: We got no IP address!\n");
        //    return 1;
        //}
        sock = lwip_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0)
        {
            unsigned int ed = GetLastError();
            printf("Socket error: %d\n", ed);
            /**vTaskDelay(10); */
            Sleep(10);
            break;
        }

        //struct Ipv4Address ip = Ipv4(127, 0, 0, 1, 10808);
        client_addr.sin_family = AF_INET;
        client_addr.sin_port = PP_HTONS(PORT);
        client_addr.sin_addr.s_addr = inet_addr(IP_ADDR);
        memset(&(client_addr.sin_zero), 0, sizeof(client_addr.sin_zero));

        while (lwip_connect(sock,
            (struct sockaddr*)&client_addr,
            sizeof(struct sockaddr)) == -1)
        {
            unsigned int ed = GetLastError();
            printf("Connect failed: %d!\n", ed);
            //closesocket(sock);
            /**vTaskDelay(10); */
            Sleep(1000);
            //break;
            continue;
        }

        printf("Connect to iperf server successful!\n");

        /**while (1) */
        /**{ */
        /**    if (write(sock, send_buf, sizeof(send_buf)) < 0) */
        /**        break; */

        /**    //vTaskDelay(1000); */
        /**    Sleep(1000); */
        /**} */

        /**closesocket(sock); */
    }

}

void
client_init(void)
{
    sys_init();
    sys_thread_new("client", client, NULL, 512, 4);
}

void client_auth() {
    unsigned char ver = 0x5;
    unsigned char nmeth = 0x1;
    unsigned char meths[255];

    unsigned char wbuf[257];
    unsigned char rbuf[1024];
    write(g_sock, wbuf, sizeof(wbuf));

    read(g_sock, rbuf, sizeof(rbuf));

    if (rbuf[0] != 0x5) {
        /**ver error */
        return;
    }
    switch (rbuf[1]) {
    case 0x0:
        break;
    case 0x1:
        /**TODO */
        break;
    case 0x2: {
        unsigned char awbuf[513];
        unsigned char arbuf[1024];
        awbuf[0] = 0x5;
        awbuf[1] = 0xFF;
        sprintf(awbuf[2], "username");
        awbuf[257] = 0xFF;
        sprintf(awbuf[258], "password");

        write(g_sock, awbuf, sizeof(awbuf));
        read(g_sock, arbuf, sizeof(arbuf));

        if (arbuf[0] != 0x5) {
            /**error */
            return;
        }
        if (arbuf[1] != 0x0) {
            /**error */
        }
    }
        break;
    case 0x80:
        /**TODO */
        break;
    case 0xFF:
        /**error */
        break;
    default:
        /**error */
        break;
    }
}

void client_connect(uint32_t addr, uint16_t port) {
    unsigned char rbuf[1024] = { 0 };
    unsigned char wbuf[1024] = { 0 };
    rbuf[0] = 0x5;
    rbuf[1] = 0x1;/**CMD */
    rbuf[3] = 0x1; /**ipv4 */
    memcpy(rbuf[4], &addr, sizeof(uint32_t));
    memcpy(rbuf[8], &port, sizeof(uint16_t));

    write(g_sock, rbuf, 10);

    read(g_sock, wbuf, sizeof(wbuf));
    if (wbuf[0] != 0x5) {
        /**error */
    }
    if (wbuf[1] != 0x0) {
        /**error */
    }
}
