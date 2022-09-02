#ifndef __LWIP_CAP_H
#define __LWIP_CAP_H

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
	__declspec(dllexport) int __stdcall start_listen(const char* tunn_name, unsigned __int32 len,
						unsigned __int32 __stdcall tcp_addr[4], unsigned __int16 tcp_port,
						unsigned __int32 __stdcall udp_addr[4], unsigned __int16 udp_port);
	/**
	 * ��ȡ����״̬
	 * ����ֵ��δ����Ϊ0�� ����Ϊ���ڼ��� 
	 */
	__declspec(dllexport) int __stdcall listen_statu();
	/**
	 * ֹͣ����
	 */
	__declspec(dllexport) void __stdcall stop_listen();
#ifdef __cplusplus
}
#endif

#endif