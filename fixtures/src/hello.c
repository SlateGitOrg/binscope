/* hello family: prints a greeting. Variants change the text and a counter. */
#include "platform.h"

#if VARIANT == 0
static const char *greeting = "Hello from the binscope test corpus";
#elif VARIANT == 1
static const char *greeting = "Hello again from the binscope test corpus";
#elif VARIANT == 2
static const char *greeting = "Greetings from the binscope corpus (variant two)";
#else
static const char *greeting = "Hello, world - binscope corpus variant three";
#endif

#if defined(BS_WINDOWS)
/* A wide string so the PE builds carry UTF-16LE text for string extraction. */
static const unsigned short wide_banner[] = u"binscope wide banner: hello";
#endif

static int repeat_count(void) { return 1 + VARIANT; }

int main(void) {
    for (int i = 0; i < repeat_count(); i++) {
        bs_print(greeting);
    }
#if defined(BS_WINDOWS)
    DWORD written = 0;
    WriteConsoleW(GetStdHandle(BS_STD_OUTPUT), wide_banner,
                  (DWORD)(sizeof(wide_banner) / 2 - 1), &written, 0);
#endif
    return 0;
}
