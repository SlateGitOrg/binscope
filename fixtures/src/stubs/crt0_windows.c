/* Entry point for the freestanding Windows builds. */
int main(void);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);
void mainCRTStartup(void) { ExitProcess((unsigned int)main()); }
