#ifndef __LWIP_CAP_H
#define __LWIP_CAP_H

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
	__declspec(dllexport) int __stdcall start_listen(const char* tunn_name, unsigned __int32 len,
						unsigned __int32 tcp_addr[4], unsigned __int16 tcp_port,
						unsigned __int32 udp_addr[4], unsigned __int16 udp_port);
	/**
	 * 获取监听状态
	 * 返回值：未监听为0， 其他为正在监听 
	 */
	__declspec(dllexport) int __stdcall listen_statu();
	/**
	 * 停止监听
	 */
	__declspec(dllexport) void __stdcall stop_listen();
#ifdef __cplusplus
}
#endif

#endif