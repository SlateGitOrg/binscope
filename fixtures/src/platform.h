/*
 * platform.h - tiny freestanding platform layer for the binscope test corpus.
 *
 * Every program in this corpus is benign: it prints a message, round-trips a
 * temp file, talks to 127.0.0.1 only, or checksums an embedded data blob.
 * The binaries exist so binscope has real ELF / PE / Mach-O inputs whose
 * provenance is fully known (built from this directory by build.sh).
 *
 * Exactly one of BS_LINUX, BS_WINDOWS, BS_DARWIN is defined by build.sh.
 */
#ifndef BINSCOPE_PLATFORM_H
#define BINSCOPE_PLATFORM_H

#ifndef VARIANT
#define VARIANT 0
#endif

typedef unsigned long bs_size;

#if defined(BS_WINDOWS)
/* Declarations only; resolved through import libraries generated from the
 * .def files in stubs/. No Windows SDK is needed. */
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
#define BS_API __declspec(dllimport) __stdcall
BS_API HANDLE GetStdHandle(DWORD);
BS_API BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
BS_API BOOL ReadFile(HANDLE, void *, DWORD, DWORD *, void *);
BS_API BOOL WriteConsoleW(HANDLE, const unsigned short *, DWORD, DWORD *, void *);
BS_API HANDLE CreateFileW(const unsigned short *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
BS_API BOOL CloseHandle(HANDLE);
BS_API BOOL DeleteFileW(const unsigned short *);
BS_API DWORD GetTempPathW(DWORD, unsigned short *);
BS_API void ExitProcess(unsigned int);
#define BS_STD_OUTPUT ((DWORD)-11)
#define BS_SECTION(name) __attribute__((section(name)))
#define BS_BLOB_SECTION BS_SECTION(".blob")
#elif defined(BS_DARWIN)
#define BS_BLOB_SECTION __attribute__((section("__DATA,__blob")))
#else /* BS_LINUX */
#define BS_BLOB_SECTION __attribute__((section(".blob")))
#endif

#if !defined(BS_WINDOWS)
/* libc entry points. On Linux these resolve against a stub libc.so.6 at link
 * time (and the real glibc at run time); on Darwin against libSystem. */
int puts(const char *);
void *fopen(const char *, const char *);
bs_size fwrite(const void *, bs_size, bs_size, void *);
bs_size fread(void *, bs_size, bs_size, void *);
int fclose(void *);
int remove(const char *);
void exit(int);
#endif

static bs_size bs_strlen(const char *s) {
    bs_size n = 0;
    while (s[n]) n++;
    return n;
}

static void bs_print(const char *s) {
#if defined(BS_WINDOWS)
    DWORD written = 0;
    WriteFile(GetStdHandle(BS_STD_OUTPUT), s, (DWORD)bs_strlen(s), &written, 0);
    WriteFile(GetStdHandle(BS_STD_OUTPUT), "\r\n", 2, &written, 0);
#else
    (void)bs_strlen;
    puts(s);
#endif
}

#endif
