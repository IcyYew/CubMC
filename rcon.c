#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


void read_specs(char* pswd, char* addr, int* port) {
    printf("Input rcon password: ");
    if ( scanf("%49s", pswd) < 1 ) {
        printf("Password failed to read (size too large)\n");
        exit(1);
    }
    printf("Input server address: ");
    if ( scanf("%15s", addr) < 1) {
        printf("Server address failed to read (size too large)\n");
        exit(1);
    }
    printf("Input server rcon port: ");
    if ( scanf("%d", port) < 1) {
        printf("Server port not integer\n");
        exit(1);
    }
    if ( *port < 1024 || *port > 65535 ) {
        printf("Server port is privileged (<1024) or invalid (>65535)\n");
        exit(1);
    }
}

int read_cmd(char* cmd) {
    printf("Input minecraft server command: ");
    if ( scanf("%99s", cmd) < 1 ) {
        return 0;
    }
    return 1;
}

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
    char addr[16] = "";
    int port = 0;
    char cmd[100] = "";
    int read_cmd_ret = 1;
    read_specs(pswd, addr, &port);
    size_t pswd_len = strlen(pswd);
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(port);
    // a conditional check for invalid address family (i.e. ret < 0) is not needed here since it is hardcoded
    if ( inet_pton(s_addr.sin_family, addr, &s_addr.sin_addr) == 0 ) {
        printf("Not a valid network address for IPv4 address family\n");
        exit(1);
    }
    if( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        printf("Failed to create socket\n");
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
    if ( (read_cmd_ret = read_cmd(cmd) ) == 0) {
        printf("Command failed to read (size too large)\n");
        close(sock);
        exit(1);
    }
    printf("cmd = %s\n", cmd);
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
    unsigned char payload_strip[1000];
    memcpy(payload_strip, packet_r + 12, r_size - 12);
    payload_strip[payload_size] = '\0';
    printf("%s", payload_strip);

    close(sock);
    return 0;
}
