/* net family: opens a TCP socket to 127.0.0.1 (loopback only), sends a ping,
 * closes. Never contacts any other host. */
#include "platform.h"

#if VARIANT == 0
static const char ping[] = "binscope loopback ping";
#elif VARIANT == 1
static const char ping[] = "binscope loopback ping (variant one)";
#elif VARIANT == 2
static const char ping[] = "loopback ping from binscope, variant two";
#else
static const char ping[] = "binscope ping over loopback - variant three";
#endif

static const unsigned short port = 7 + VARIANT; /* echo-ish ports on localhost */

struct bs_sockaddr_in {
#if defined(BS_DARWIN)
    unsigned char len;
    unsigned char family;
#else
    unsigned short family;
#endif
    unsigned short port;
    unsigned int addr;
    unsigned char zero[8];
};

#if defined(BS_WINDOWS)
typedef __UINTPTR_TYPE__ SOCKET;
struct bs_wsadata { unsigned char opaque[512]; };
BS_API int WSAStartup(unsigned short, struct bs_wsadata *);
BS_API int WSACleanup(void);
BS_API SOCKET socket(int, int, int);
BS_API int connect(SOCKET, const void *, int);
BS_API int send(SOCKET, const char *, int, int);
BS_API int closesocket(SOCKET);
BS_API unsigned short htons(unsigned short);
#else
int socket(int, int, int);
int connect(int, const void *, unsigned int);
long send(int, const void *, bs_size, int);
int close(int);
unsigned short htons(unsigned short);
#endif

int main(void) {
    struct bs_sockaddr_in sa;
    for (int i = 0; i < 8; i++) sa.zero[i] = 0;
#if defined(BS_DARWIN)
    sa.len = sizeof(sa);
#endif
    sa.family = 2;            /* AF_INET */
    sa.port = htons(port);
    sa.addr = 0x0100007f;     /* 127.0.0.1 in network byte order */
#if defined(BS_WINDOWS)
    struct bs_wsadata wsa;
    if (WSAStartup(0x0202, &wsa) != 0) return 1;
    SOCKET s = socket(2, 1, 6);
    int ok = connect(s, &sa, sizeof(sa)) == 0;
    if (ok) send(s, ping, (int)sizeof(ping) - 1, 0);
    closesocket(s);
    WSACleanup();
#else
    int s = socket(2, 1, 6);
    int ok = connect(s, &sa, sizeof(sa)) == 0;
    if (ok) send(s, ping, sizeof(ping) - 1, 0);
    close(s);
#endif
    bs_print(ok ? "loopback ping sent" : "loopback ping: nobody listening");
    return 0;
}
