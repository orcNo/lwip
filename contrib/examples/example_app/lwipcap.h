#ifndef __LWIP_CAP_H
#define __LWIP_CAP_H

#include "client.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * 开始lwipcap监听
	 * tunn_name: wireguard tunnel描述，默认为 "WireGuard Tunnel"
	 * socks_addr: socks5服务器的ip   ip4的话 前 12位置都为0, 12-16 位置存储ip4  
	 * socks_port: socks5服务器的port
	 * udp_addr: udp传递的ip
	 * udp_port: udp传递的端口  ip4的话 前 12位置都为0, 12-16 位置存储ip4  
	 */
#if defined (_MSC_VER)
	 DLL_EXPORT int STDCALL start_listen(const char* tunn_name, uint32_t len,
						uint32_t tcp_addr[4], uint16_t tcp_port,
						uint32_t udp_addr[4], uint16_t udp_port);
#else
	 DLL_EXPORT int STDCALL start_listen(uint32_t tun_addr[4],
						uint32_t tcp_addr[4], uint16_t tcp_port,
						uint32_t udp_addr[4], uint16_t udp_port);
#endif
	/**
	 * 获取监听状态
	 * 返回值：未监听为0， 其他为正在监听 
	 */
	DLL_EXPORT int STDCALL listen_statu(void);
	/**
	 * 停止监听
	 */
	DLL_EXPORT void STDCALL stop_listen(void);
#ifdef __cplusplus
}
#endif

#endif
