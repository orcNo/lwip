#ifndef __LWIP_CAP_H
#define __LWIP_CAP_H

#include "client.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * ��ʼlwipcap����
	 * tunn_name: wireguard tunnel������Ĭ��Ϊ "WireGuard Tunnel"
	 * socks_addr: socks5��������ip   ip4�Ļ� ǰ 12λ�ö�Ϊ0, 12-16 λ�ô洢ip4  
	 * socks_port: socks5��������port
	 * udp_addr: udp���ݵ�ip
	 * udp_port: udp���ݵĶ˿�  ip4�Ļ� ǰ 12λ�ö�Ϊ0, 12-16 λ�ô洢ip4  
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
	 * ��ȡ����״̬
	 * ����ֵ��δ����Ϊ0�� ����Ϊ���ڼ��� 
	 */
	DLL_EXPORT int STDCALL listen_statu(void);
	/**
	 * ֹͣ����
	 */
	DLL_EXPORT void STDCALL stop_listen(void);
#ifdef __cplusplus
}
#endif

#endif
