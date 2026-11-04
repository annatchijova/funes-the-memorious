/* Host fixture for Level 1 evidence exercises. Deterministic output.
 * Exit 0 on success; argument "fail" exits 3 so failing-test evidence can
 * be demonstrated without a broken build. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "fail") == 0) {
        printf("host-hello: deliberate failure requested\n");
        return 3;
    }
    if (argc > 1 && strcmp(argv[1], "--selftest") == 0) {
        printf("host-hello selftest: ok value=42\n");
        return 42 == 42 ? 0 : 1;
    }
    printf("host-hello: value=42\n");
    return 0;
}
