/* Minimal _start for the freestanding Linux builds: call main, then exit(). */
int main(void);
void exit(int);
__attribute__((force_align_arg_pointer)) void _start(void) { exit(main()); }
