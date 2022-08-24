#ifndef __CLIENT__H
#define __CLIENT__H

#ifdef __cplusplus
extern  "C" {
#endif

#define DLL_EXPORT __declspec(dllexport)

#define SHANDLE void*
#define MAKE_ADDR(a, b, c, d) (a << 24) | (b << 16) | (c << 8) | (d)

	DLL_EXPORT SHANDLE sclient_connect(unsigned __int32 saddr[4], unsigned  __int16 sport,
								unsigned __int32 daddr[4], unsigned __int16 dport);

	DLL_EXPORT int sclient_send(SHANDLE handle, const char* buf, unsigned __int32 len);
	DLL_EXPORT int sclient_recv(SHANDLE handle, const char* buf, unsigned __int32 len);

	DLL_EXPORT int sclient_close(SHANDLE handle);
#ifdef __cplusplus
}
#endif

#endif