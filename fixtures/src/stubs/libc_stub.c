/* Link-time stand-in for libc.so.6: gives the linker the symbol names so the
 * output ELF records them as dynamic imports (DT_NEEDED libc.so.6). Bodies are
 * never used - at run time the real C library provides these. */
#define STUB(name) void name(void) {}
STUB(puts) STUB(fopen) STUB(fwrite) STUB(fread) STUB(fclose) STUB(remove)
STUB(exit) STUB(socket) STUB(connect) STUB(send) STUB(close) STUB(htons)
