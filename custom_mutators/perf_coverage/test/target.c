#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char buf[1024];
    ssize_t len;

    if (argc > 1) {
        FILE *f = fopen(argv[1], "r");
        if (!f) return 1;
        len = fread(buf, 1, sizeof(buf)-1, f);
        fclose(f);
    } else {
        len = read(0, buf, sizeof(buf)-1);
    }

    if (len <= 0) return 0;
    buf[len] = 0;

    // Simple branches for coverage testing
    if (len > 4 && buf[0] == 'F') {
        printf("Branch F\n");
        if (buf[1] == 'U') {
            printf("Branch FU\n");
            if (buf[2] == 'Z') {
                printf("Branch FUZ\n");
                if (buf[3] == 'Z') {
                    printf("Branch FUZZ\n");
                }
            }
        }
    }

    if (buf[0] == 'A') {
        printf("Branch A\n");
    }

    if (buf[0] == 'B') {
        printf("Branch B\n");
    }

    return 0;
}
