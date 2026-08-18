#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


// get char loop isn't my style, this uses scanf to purge stdin up to a newline (for cases in which stdin violates our length requirements for str
// getchar() eats the newline character. There are some other concerns such as EOF or no newline character to be addressed, works for now,
// considering the usecase of this utility, further input validation is a little unnecessary. Assuming fgets() did read input with a newline within our
// expected parameters, we add a null terminator in the index of the newline
int stdin_consumer(char* str) {
    if (str[strlen(str) - 1] != '\n') {
        scanf("%*[^\n]");
        getchar();
        return 1;
    }
    str[strlen(str) - 1] = '\0';
    return 0;
}

int read_str(char* prepend_str, char* str, size_t count) {
    printf("Input %s: ", prepend_str);
    // this is very inelegant, should be fine for now, returning 0 also prints error in main, which is fine, i guess...
    if ( fgets(str, count, stdin) == NULL ) {
        printf("Input error or EOF\n");
        return 0;
    }
    if (stdin_consumer(str)) {
        return 0;
    }
    return 1;
}

// plan for exiting gracefully, could turn into a messy function depending on the state of the application when called
// void exit_graceful(int sock)


int main() {
    unsigned char packet_w[1460];
    unsigned char packet_r[4110];
    ssize_t w_size;
    ssize_t r_size;
    int32_t packet_len;
    int32_t packet_rid;
    int32_t packet_type;
    struct sockaddr_in s_addr = {0};
    int sock;
    char pswd[50] = "";
    // allow for maximum size address, allocated 17 bytes to account for \n and \0 in current input validation
    char addr[17] = "";
    // allow for ports up to max of 5 chars, allocated 7 bytes to account for \n and \0 in current input validation
    char port[7] = "";
    char cmd[1440] = ""; // not exactly its maximum allocation to give some breathing room, upper bound may even need lowered
    int l_port; 
    size_t pswd_len; 

    if( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        printf("Failed to create socket\n");
        exit(1);
    }

    if ( read_str("password", pswd, sizeof(pswd)) == 0) {
        printf("Password too large.\n");
        exit(1);
    }
    if ( read_str("address", addr, sizeof(addr)) == 0) {
        printf("Address too large\n");
        exit(1);
    }
    read_str("port", port, sizeof(port));
    l_port = strtol(port, NULL, 10); // need to retain endptr eventually to prevent garbage input
    if ( l_port < 1024 || l_port > 65535 ) {
        printf("Port not within valid range.\n");
        exit(1);
    }
    pswd_len = strlen(pswd);
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(l_port);
    // a conditional check for invalid address family (i.e. ret < 0) is not needed here since it is hardcoded
    if ( inet_pton(s_addr.sin_family, addr, &s_addr.sin_addr) == 0 ) {
        printf("Not a valid network address for IPv4 address family\n");
        exit(1);
    }
    if ( connect(sock, (struct sockaddr*)&s_addr, sizeof(s_addr)) < 0 ) {
        printf("Socket failed to connect on %s\n", addr);
        close(sock);
        exit(1);
    }
    // Construct auth packet
    packet_len = pswd_len + sizeof(packet_type) + sizeof(packet_rid) + 2;
    packet_type = 3;
    packet_rid = 1;
    memcpy(packet_w, &packet_len, 4);
    memcpy(packet_w + 4, &packet_rid, 4);
    memcpy(packet_w + 8, &packet_type, 4);
    memcpy(packet_w + 12, pswd, pswd_len + 2);
    packet_len += sizeof(packet_len);
    if ( (w_size = write(sock, packet_w, packet_len) ) < 0) {
        printf("Packet failed to send\n");
        close(sock);
        exit(1);
    }
    if ( (r_size = read(sock, packet_r, sizeof(packet_r))) < 0) {
        printf("Packet failed to read\n");
        close(sock);
        exit(1);
    }

    // clean up auth packet state
    memset(packet_w, 0, sizeof(packet_w));
    memset(packet_r, 0, sizeof(packet_r));
    if ( read_str("command", cmd, sizeof(cmd)) == 0 ) {
        printf("Command too large");
        close(sock);
        exit(1);
    }
    packet_len = strlen(cmd) + sizeof(packet_type) + sizeof(packet_rid) + 2;
    packet_rid = 2;
    packet_type = 2;
    memcpy(packet_w, &packet_len, 4);
    memcpy(packet_w + 4, &packet_rid, 4);
    memcpy(packet_w + 8, &packet_type, 4);
    memcpy(packet_w + 12, cmd, strlen(cmd) + 2);
    packet_len += sizeof(packet_len);
    if ( (w_size = write(sock, packet_w, packet_len) ) < 0) {
        printf("Packet failed to send\n");
        close(sock);
        exit(1);
    }
    if ( (r_size = read(sock, packet_r, sizeof(packet_r))) < 0) {
        printf("Packet failed to read\n");
        close(sock);
        exit(1);
    }
    size_t payload_size = r_size - 14;
    unsigned char payload_strip[payload_size + 1];
    memcpy(payload_strip, packet_r + 12, payload_size);
    payload_strip[payload_size] = '\0';
    printf("%s\n", payload_strip);

    close(sock);
    return 0;
}
