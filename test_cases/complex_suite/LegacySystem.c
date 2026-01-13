#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[64];
    // 1. Stack Buffer Overflow - True Positive
    // 危险函数 strcpy，没有检查长度
    strcpy(buffer, input); 
    
    // 2. Format String Vulnerability - True Positive
    printf(input);
}

void safe_function(char *input) {
    char buffer[64];
    // 安全版本 - True Negative
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
