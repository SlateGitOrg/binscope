/* files family: writes a small temp file, reads it back, deletes it. */
#include "platform.h"

#if VARIANT == 0
static const char payload[] = "binscope file round-trip payload (v0)";
#elif VARIANT == 1
static const char payload[] = "binscope file round-trip payload, variant one";
#elif VARIANT == 2
static const char payload[] = "round-trip payload for binscope: variant two";
#else
static const char payload[] = "binscope round-trip payload / variant three / extra";
#endif

#if defined(BS_WINDOWS)
static const unsigned short temp_name[] = u"binscope_roundtrip.tmp";
#define GENERIC_READ 0x80000000UL
#define GENERIC_WRITE 0x40000000UL
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3

static int roundtrip(void) {
    unsigned short path[260];
    DWORD n = GetTempPathW(200, path);
    for (DWORD i = 0; temp_name[i]; i++) path[n++] = temp_name[i];
    path[n] = 0;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    DWORD done = 0;
    WriteFile(h, payload, sizeof(payload), &done, 0);
    CloseHandle(h);
    char back[sizeof(payload)];
    h = CreateFileW(path, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
    ReadFile(h, back, sizeof(back), &done, 0);
    CloseHandle(h);
    DeleteFileW(path);
    return done == sizeof(payload) ? 0 : 1;
}
#else
static int roundtrip(void) {
    const char *path = "/tmp/binscope_roundtrip.tmp";
    void *f = fopen(path, "wb");
    if (!f) return 1;
    fwrite(payload, 1, sizeof(payload), f);
    fclose(f);
    char back[sizeof(payload)];
    f = fopen(path, "rb");
    if (!f) return 1;
    bs_size got = fread(back, 1, sizeof(back), f);
    fclose(f);
    remove(path);
    return got == sizeof(payload) ? 0 : 1;
}
#endif

int main(void) {
    int rc = 0;
    for (int i = 0; i <= VARIANT; i++) rc |= roundtrip();
    bs_print(rc == 0 ? "file round-trip ok" : "file round-trip failed");
    return rc;
}
