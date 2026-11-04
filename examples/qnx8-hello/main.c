/* QNX 8.0 demonstration fixture. This file is the artifact under
 * investigation for Level 2; compiling it with a host compiler produces a
 * host binary and must be labeled VERIFIED_HOST_ONLY, never QNX evidence.
 * With QNX's qcc it reports the target it was built for. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "fail") == 0) {
        printf("qnx8-hello: deliberate failure requested\n");
        return 3;
    }
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0) {
        printf("qnx8-hello selftest: ok value=42\n");
        return 0;
    }
#if defined(__QNXNTO__)
    printf("qnx8-hello: value=42 target=qnx\n");
#else
    printf("qnx8-hello: value=42 target=host-not-qnx\n");
#endif
    return 0;
}
