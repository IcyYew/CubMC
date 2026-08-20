#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#define RCON_LEN_OFF    0
#define RCON_RID_OFF    4
#define RCON_TYP_OFF    8
#define RCON_PLD_OFF   12
#define SNTL_RID_OFF   10


// get char loop isn't my style, this uses scanf to purge stdin up to a newline (for cases in which stdin violates our length requirements for str
// getchar() eats the newline character. There are some other concerns such as EOF or no newline character to be addressed, works for now,
// considering the usecase of this utility, further input validation is a little unnecessary. Assuming fgets() did read input with a newline within our
// expected parameters, we add a null terminator in the index of the newline
int stdin_consumer(char* str) {
    size_t str_len = strlen(str);
    if ( str_len == 0) {
        printf("Empty string\n");
        return 1;
    }
    if ( str[str_len - 1] != '\n') {
        if ( scanf("%*[^\n]") == EOF ) {
            printf("EOF\n");
            return 1;
        }
        getchar();
        return 1;
    }
    str[str_len - 1] = '\0';
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

int establish_connection(struct sockaddr_in s_addr, int in_sock) {
    int sock;
    if ( in_sock >= 0 ) {
        close(in_sock);
    }
    if( (sock = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        printf("Failed to create socket\n");
        exit(1);
    }
    if ( connect(sock, (struct sockaddr*)&s_addr, sizeof(s_addr)) < 0 ) {
        printf("Socket failed to connect\n");
        close(sock);
        exit(1);
    }
    return sock;
}


// plan for exiting gracefully, could turn into a messy function depending on the state of the application when called
// void exit_graceful(int sock)



// Constructs an RCON packet, unsigned char* packet is to be written into, unsigned char* payload is the string payload passed from the function call
// size_t payload_count is the length of that payload, and packet_type is what type of packet we have
// Internally, the variable packet_len is used as both the RCON length field and then re-used as the overrall packet buffer size
// We allocate two extra bytes to packet_len to account for the two null terminators expected by the RCON protocol, one for the payload itself and
// another for the null padding
// The function returns packet_len as the total packet buffer size for use in subsequent read/write handling after this function is called
// An important note that this function relies on the global variable rid_iter, and the expectation is that rid_iter be iterated upon after the packet
// referenced by it is completely serialized and handled after this function call
int32_t packet_constructor(unsigned char* packet, const char* payload, size_t payload_count, int32_t packet_type, int packet_rid) {
    // RCON length field
    int32_t packet_len = sizeof(packet_type) + sizeof(packet_rid) + payload_count + 2;
    memcpy(packet, &packet_len, sizeof(packet_len));
    memcpy(packet + RCON_RID_OFF, &packet_rid, sizeof(packet_rid));
    memcpy(packet + RCON_TYP_OFF, &packet_type, sizeof(packet_type));
    memcpy(packet + RCON_PLD_OFF, payload, payload_count);
    // Re-use variable, now is total buffer size
    packet_len += sizeof(packet_len);
    // write two null terminators per RCON spec
    packet[packet_len - 2] = '\0';
    packet[packet_len - 1] = '\0';
    return packet_len;
}

// no return value, a failure exits the program currently anyways. works for now, not permanent anyways
void intake_setup(char* pswd, char* addr, char* port, size_t pswd_count, size_t addr_count, size_t port_count, struct sockaddr_in* s_addr) {
    char* strtol_endptr;
    int l_port;
    if ( read_str("password", pswd, pswd_count) == 0) {
        printf("Password too large.\n");
        exit(1);
    }
    if ( read_str("address", addr, addr_count) == 0) {
        printf("Address too large\n");
        exit(1);
    }
    read_str("port", port, port_count);
    l_port = strtol(port, &strtol_endptr, 10);
    if ( *strtol_endptr != '\0' || strtol_endptr == port ) {
        printf("No port conversion, not numerical or garbage-addled\n");
        exit(1);
    }

    if ( l_port < 1024 || l_port > 65535 ) {
        printf("Port not within valid range.\n");
        exit(1);
    }
    s_addr->sin_family = AF_INET;
    s_addr->sin_port = htons(l_port);
    // a conditional check for invalid address family (i.e. ret < 0) is not needed here since it is hardcoded
    if ( inet_pton(s_addr->sin_family, addr, &s_addr->sin_addr) == 0 ) {
        printf("Not a valid network address for IPv4 address family\n");
        exit(1);
    }
}

// when other helper functions are made this should be cleaner
// much like with intake_setup, returns nothing becauses we exit in failure, this one will need changed!!!
void authenticate(const char* pswd, size_t pswd_len, int32_t packet_rid, unsigned char* packet_w, unsigned char* packet_r,
        size_t packet_r_count, int in_sock) {
    int32_t packet_type = 3; // declared locally, no need to pass
    ssize_t w_size;
    ssize_t r_size;
    int32_t packet_rid_auth;
    int32_t packet_len;
    packet_len = packet_constructor(packet_w, pswd, pswd_len, packet_type, packet_rid);
    if ( (w_size = write(in_sock, packet_w, packet_len) ) < 0) {
        printf("Packet failed to send\n");
        close(in_sock);
        exit(1);
    }
    if ( (r_size = read(in_sock, packet_r, packet_r_count)) < 0) {
        printf("Packet failed to read\n");
        close(in_sock);
        exit(1);
    }

    memcpy(&packet_rid_auth, packet_r + RCON_RID_OFF, sizeof(packet_rid_auth));
    memcpy(&packet_type, packet_r + RCON_TYP_OFF, sizeof(packet_type));
    if (packet_rid != 1 || packet_type != 2) {
        printf("Auth unsuccessful\n");
        close(in_sock);
        exit(1);
    }

}



int main() {
    unsigned char packet_w[1460];
    unsigned char packet_r[4110];
    unsigned char packet_s[1460];
    char sentinel_pload[] = "Invalid payload";
    ssize_t w_size;
    ssize_t r_size;
    ssize_t s_size;
    int32_t packet_len;
    int32_t packet_rid = 1;
    int32_t packet_s_rid;
    int32_t packet_type;
    int32_t sentinel_packet_rid;
    struct sockaddr_in s_addr = {0};
    int sock;
    char pswd[50] = "";
    // allow for maximum size address, allocated 17 bytes to account for \n and \0 in current input validation
    char addr[17] = "";
    // allow for ports up to max of 5 chars, allocated 7 bytes to account for \n and \0 in current input validation
    char port[7] = "";
    char cmd[1440] = ""; // not exactly its maximum allocation to give some breathing room, upper bound may even need lowered

    // these two variables can be generalized into a payload_len
    size_t pswd_len;
    size_t cmd_len;
    size_t sentinel_len;
    
    size_t bytes_in_buffer = 0;

    int connection_ok = 1;
    intake_setup(pswd, addr, port, sizeof(pswd), sizeof(addr), sizeof(port), &s_addr);

    pswd_len = strlen(pswd);

    sock = establish_connection(s_addr, -1);

    authenticate(pswd, pswd_len, packet_rid, packet_w, packet_r, sizeof(packet_r), sock);

    packet_rid++;

    while(1) {
        // clean-up packet state
        memset(packet_w, 0, sizeof(packet_w));
        memset(packet_r, 0, sizeof(packet_r));
        bytes_in_buffer = 0;
        if ( read_str("command", cmd, sizeof(cmd)) == 0 ) {
            printf("Command too large\n");
            continue;
        }
        if ( strcmp(cmd, "exit") == 0) {
            break;
        }
        cmd_len = strlen(cmd);
        packet_type = 2;
        packet_len = packet_constructor(packet_w, cmd, cmd_len, packet_type, packet_rid);
        while ( (int32_t)bytes_in_buffer < packet_len ) {
            if ( (w_size = write(sock, packet_w + bytes_in_buffer, packet_len - bytes_in_buffer) ) < 0) {
                printf("Packet failed to send\n");
                continue;
            }
            if ( w_size == 0 ) {
                // connection broken, need to re-establish on new sock
            }
            bytes_in_buffer += w_size;
        }

        bytes_in_buffer = 0;
        while (1) {
            while ( bytes_in_buffer < sizeof(packet_len)) {
                if ( (r_size = read(sock, packet_r + bytes_in_buffer, sizeof(packet_r) - bytes_in_buffer)) < 0) {
                    printf("Packet failed to read\n");
                    connection_ok = 0;
                    break;
                }
                if ( r_size == 0 ) {
                    // connection broken, need to re-establish on new sock, massive overhaul
                }
                bytes_in_buffer += r_size;
            }

            memcpy(&packet_len, packet_r + RCON_LEN_OFF, sizeof(packet_len));
            packet_len += sizeof(packet_len);

            while ( (int32_t)bytes_in_buffer < packet_len ) {
                if ( (r_size = read(sock, packet_r + bytes_in_buffer, sizeof(packet_r) - bytes_in_buffer)) < 0) {
                    printf("Packet failed to read\n");
                    connection_ok = 0;
                    break;
                }
                if ( r_size == 0) {
                    // connection broken
                }
                bytes_in_buffer += r_size;
            }
        
            size_t payload_size = packet_len - 14;
            unsigned char payload_strip[payload_size + 1];
            memcpy(payload_strip, packet_r + 12, payload_size);
            payload_strip[payload_size] = '\0';
            bytes_in_buffer -= packet_len;
            memcpy(&packet_s_rid, packet_r + RCON_RID_OFF, sizeof(packet_s_rid));
            if ( packet_s_rid == sentinel_packet_rid ) {
                break;
            }
            memmove(packet_r, packet_r + packet_len, bytes_in_buffer);


            // temporary variable to fix regression
            size_t bytes_in_buffer_s = 0;
            packet_type = 200;
            sentinel_packet_rid = packet_rid + SNTL_RID_OFF;
            sentinel_len = strlen(sentinel_pload);
            packet_len = packet_constructor(packet_s, sentinel_pload, sentinel_len, packet_type, sentinel_packet_rid);
            while ( (int32_t)bytes_in_buffer_s < packet_len ) {
                if ( (s_size = write(sock, packet_s + bytes_in_buffer_s, packet_len - bytes_in_buffer_s) ) < 0) {
                    printf("Packet failed to send\n");
                    continue;
                }
                if ( s_size == 0 ) {
                    // connection broken, need to re-establish on new sock
                }
                bytes_in_buffer_s += s_size;
            }
            printf("%s\n", payload_strip);

        }

        if (connection_ok == 0) {
            break;
        }

        packet_rid++;
    }
    close(sock);
    return 0;
}
