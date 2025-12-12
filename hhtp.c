/*
    Mini HTTP Server with Basic Authentication
    Works on Windows (Code::Blocks, Winsock2)

    Compile: link with ws2_32.lib
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080
#define USER "admin"
#define PASS "1234"

// Simple Base64 decoder
char *base64_decode(const char *input) {
    const char *b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len = strlen(input);
    char *out = (char*)malloc(len * 3 / 4 + 1);
    int val = 0, valb = -8, i, j;
    for (i = 0, j = 0; i < len; i++) {
        unsigned char c = input[i];
        if (c == '=' || c == '\r' || c == '\n') break;
        const char *p = strchr(b64_table, c);
        if (!p) continue;
        val = (val << 6) + (p - b64_table);
        valb += 6;
        if (valb >= 0) {
            out[j++] = (char)((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    out[j] = '\0';
    return out;
}

int main() {
    WSADATA wsa;
    SOCKET server_fd, new_socket;
    struct sockaddr_in server, client;
    int c, recv_size;
    char buffer[4096];

    printf("Starting Mini HTTP Server on port %d...\n", PORT);

    // Init Winsock
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("WSAStartup failed. Error Code : %d\n", WSAGetLastError());
        return 1;
    }

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Could not create socket : %d\n", WSAGetLastError());
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Bind failed with error code : %d\n", WSAGetLastError());
        return 1;
    }

    listen(server_fd, 3);

    printf("Waiting for connections...\n");

    c = sizeof(struct sockaddr_in);

    while ((new_socket = accept(server_fd, (struct sockaddr *)&client, &c)) != INVALID_SOCKET) {
        memset(buffer, 0, sizeof(buffer));
        recv_size = recv(new_socket, buffer, sizeof(buffer), 0);
        if (recv_size > 0) {
            printf("Request:\n%s\n", buffer);

            // Find Authorization header
            char *auth_header = strstr(buffer, "Authorization: Basic ");
            if (auth_header) {
                auth_header += strlen("Authorization: Basic ");
                char *end = strstr(auth_header, "\r\n");
                if (end) *end = '\0'; // terminate string at end of line

                // Decode credentials
                char *decoded = base64_decode(auth_header);

                // Compare with expected USER:PASS
                char expected[64];
                sprintf(expected, "%s:%s", USER, PASS);

                if (strcmp(decoded, expected) == 0) {
                    // Auth success
                    char response[] =
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/html\r\n\r\n"
                        "<h1>Welcome! You are authenticated.</h1>";
                    send(new_socket, response, strlen(response), 0);
                } else {
                    // Wrong username or password
                    char response[] =
                        "HTTP/1.1 401 Unauthorized\r\n"
                        "WWW-Authenticate: Basic realm=\"MiniServer\"\r\n"
                        "Content-Type: text/html\r\n\r\n"
                        "<h1>401 Unauthorized (Bad credentials)</h1>";
                    send(new_socket, response, strlen(response), 0);
                }
                free(decoded);
            } else {
                // No Authorization header → ask for credentials
                char response[] =
                    "HTTP/1.1 401 Unauthorized\r\n"
                    "WWW-Authenticate: Basic realm=\"MiniServer\"\r\n"
                    "Content-Type: text/html\r\n\r\n"
                    "<h1>401 Unauthorized</h1>";
                send(new_socket, response, strlen(response), 0);
            }
        }
        closesocket(new_socket);
    }

    if (new_socket == INVALID_SOCKET) {
        printf("accept failed with error code : %d\n", WSAGetLastError());
        return 1;
    }

    closesocket(server_fd);
    WSACleanup();

    return 0;
}
