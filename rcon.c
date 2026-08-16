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
        printf("Server port failed to read\n");
        exit(1);
    }
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
    read_specs(pswd, addr, &port);
    printf("port = %d\n", port);
    printf("addr = %s\n", addr);
    printf("pswd = %s\n", pswd);
    size_t pswd_len = strlen(pswd);
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(port); // needs bounds checking, though conditional in read_specs should prevent...
    if ( inet_pton(s_addr.sin_family, addr, &s_addr.sin_addr) < 0 ) {
        printf("Failed to convert address\n");
        exit(1);
    }
    //printf("Address converted\n");
    if( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        printf("Failed to create socket\n");
        exit(1);
    }
    //printf("Socket created\n");
    if ( connect(sock, (struct sockaddr*)&s_addr, sizeof(s_addr)) < 0 ) {
        printf("Socket failed to connect on %s\n", addr);
        close(sock);
        exit(1);
    }
    //printf("Connected\n");
    // Construct auth packet
    packet_len = pswd_len + sizeof(packet_type) + sizeof(packet_rid) + 2;
    packet_type = 3;
    packet_rid = 1;
    memcpy(packet_w, &packet_len, 4);
    memcpy(packet_w + 4, &packet_rid, 4);
    memcpy(packet_w + 8, &packet_type, 4);
    memcpy(packet_w + 12, pswd, pswd_len + 2);
    packet_len += sizeof(packet_len);
    printf("password length = %ld\n", pswd_len);
    if ( (w_size = write(sock, packet_w, packet_len) ) < 0) {
        printf("Packet failed to send\n");
        close(sock);
        exit(1);
    }
    /*printf("wrote %ld bytes\n", w_size);
    for(size_t i = 0; i < (size_t) w_size; i++)
        printf("%02x ", packet_w[i]);*/
    if ( (r_size = read(sock, packet_r, sizeof(packet_r))) < 0) {
        printf("Packet failed to read\n");
        close(sock);
        exit(1);
    }

    printf("wrote %ld bytes\n", r_size);
    for(size_t i = 0; i < (size_t) r_size; i++)
        printf("%02x ", packet_r[i]);

    return 0;
}
