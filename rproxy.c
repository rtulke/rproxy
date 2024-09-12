/*
 * rproxy - A simple multithreaded HTTP/HTTPS proxy server
 *
 * Author: Robert Tulke
 * Email: rt@debian.sh
 * Version: 1.1.0
 * License: GPL v3.0
 *
 * Description:
 * This program implements a basic multithreaded HTTP/HTTPS proxy server in C. It
 * listens for incoming HTTP/HTTPS connections, forwards requests to the target
 * server, and relays the responses back to the client.
 *
 * Features:
 * - Supports multithreading using pthreads.
 * - Detects HTTP and HTTPS connections.
 * - Configurable listen IP, running port, allowed hosts, and blacklisted URLs via command-line or configuration file.
 * - Config Generator
 * - Verbose mode for detailed connection logging.
 *
 * Usage:
 *   rproxy [OPTIONS]
 *
 * Options:
 *   -p, --port <port>          Specify the port to listen on (default: 8080)
 *   -l, --listen <ip>          Specify the IP address to listen on (default: 0.0.0.0)
 *   -a, --allowed-hosts <list> Comma-separated list of allowed hosts or IPs
 *   -b, --black-list <list>    Comma-separated list of blacklisted URLs, IPs, or IP ranges
 *   -v, --verbose              Enable verbose output
 *   -g, --generate-config      Generate configuration file in ~/.rproxy.conf
 *   -h, --help                 Display this help message
 *   -V, --version              Display the program version
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>

#define BUFFER_SIZE 4096
#define VERSION "1.1.0"
#define CONFIG_FILE "~/.rproxy.conf" // Standard path to the configuration file
#define FALLBACK_LISTEN_IP "0.0.0.0"
#define FALLBACK_PORT 8080
#define FALLBACK_ALLOWED_HOSTS "*"
#define MAX_BLACKLIST_ENTRIES 100

// Forward declaration of the handle_https function
void handle_https(int client_socket, const char *hostname, int port);

// Configuration structure to store program settings
typedef struct {
    char listen_ip[16];       // listen IP
    int port;                 // running port
    char allowed_hosts[1024]; // List of allowed hosts
    char black_list[MAX_BLACKLIST_ENTRIES][256]; // Blacklist of URLs or IPs
    int black_list_count;     // Number of blacklisted entries
    int verbose;              // Flag for verbose output
} Config;

// Structure for passing arguments to threads
typedef struct {
    int client_socket;
    Config *config;
    struct sockaddr_in client_addr;
} ThreadArgs;

// Function to check for root privileges if the port is below 1024
void check_root_permissions(int port) {
    if (port < 1024 && geteuid() != 0) {
        fprintf(stderr, "Error: The program must be run as root to use a port below 1024.\n");
        exit(EXIT_FAILURE);
    }
}

// Function to display the help message
void print_help() {
    printf("Usage: rproxy [OPTIONS]\n");
    printf("A simple multithreaded HTTP/HTTPS proxy server.\n\n");
    printf("Options:\n");
    printf("  -p, --port <port>          Specify the port to listen on (default: 8080)\n");
    printf("  -l, --listen <ip>          Specify the IP address to listen on (default: 0.0.0.0)\n");
    printf("  -a, --allowed-hosts <list> Comma-separated list of allowed hosts or IPs\n");
    printf("  -b, --black-list <list>    Comma-separated list of blacklisted URLs, IPs, or IP ranges\n");
    printf("  -v, --verbose              Enable verbose output\n");
    printf("  -g, --generate-config      Generate configuration file in ~/.rproxy.conf\n");
    printf("  -h, --help                 Display this help message\n");
    printf("  -V, --version              Display the program version\n");
    exit(0);
}

// Function to display the version of the program
void print_version() {
    printf("rproxy version %s\n", VERSION);
    exit(0);
}

// Function to generate a configuration file based on fallback variables
void generate_config() {
    char config_path[256];
    snprintf(config_path, sizeof(config_path), "%s/.rproxy.conf", getenv("HOME"));

    FILE *file = fopen(config_path, "w");
    if (file == NULL) {
        perror("Error creating configuration file");
        exit(1);
    }

    fprintf(file, "listen=%s\n", FALLBACK_LISTEN_IP);
    fprintf(file, "port=%d\n", FALLBACK_PORT);
    fprintf(file, "allowed_hosts=%s\n", FALLBACK_ALLOWED_HOSTS);
    fprintf(file, "black_list=\n"); // Blacklist is empty initially

    fclose(file);
    printf("Configuration file created at %s\n", config_path);
    exit(0);
}

// Function to load the configuration from a file
void load_config_file(Config *config) {
    char config_path[256];
    snprintf(config_path, sizeof(config_path), "%s/.rproxy.conf", getenv("HOME"));

    FILE *file = fopen(config_path, "r");
    if (file == NULL) {
        printf("No configuration file found at %s. Using fallback variables.\n", config_path);
        strcpy(config->listen_ip, FALLBACK_LISTEN_IP);
        config->port = FALLBACK_PORT;
        strcpy(config->allowed_hosts, FALLBACK_ALLOWED_HOSTS);
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "listen=", 7) == 0) {
            sscanf(line + 7, "%15s", config->listen_ip);
        } else if (strncmp(line, "port=", 5) == 0) {
            config->port = atoi(line + 5);
        } else if (strncmp(line, "allowed_hosts=", 14) == 0) {
            sscanf(line + 14, "%1023[^\n]", config->allowed_hosts);
        } else if (strncmp(line, "black_list=", 11) == 0) {
            char *blacklist = line + 11;
            char *token = strtok(blacklist, ",");
            while (token != NULL && config->black_list_count < MAX_BLACKLIST_ENTRIES) {
                strncpy(config->black_list[config->black_list_count++], token, 255);
                token = strtok(NULL, ",");
            }
        }
    }

    fclose(file);
    printf("Configuration loaded from %s\n", config_path);
}

// Function to parse command-line arguments
void parse_arguments(int argc, char *argv[], Config *config) {
    struct option long_options[] = {
        {"port", required_argument, 0, 'p'},
        {"listen", required_argument, 0, 'l'},
        {"allowed-hosts", required_argument, 0, 'a'},
        {"black-list", required_argument, 0, 'b'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {"generate-config", no_argument, 0, 'g'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:a:b:vhVg", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                config->port = atoi(optarg);
                break;
            case 'l':
                strncpy(config->listen_ip, optarg, sizeof(config->listen_ip) - 1);
                break;
            case 'a':
                strncpy(config->allowed_hosts, optarg, sizeof(config->allowed_hosts) - 1);
                break;
            case 'b': {
                char *token = strtok(optarg, ",");
                while (token != NULL && config->black_list_count < MAX_BLACKLIST_ENTRIES) {
                    strncpy(config->black_list[config->black_list_count++], token, 255);
                    token = strtok(NULL, ",");
                }
                break;
            }
            case 'v':
                config->verbose = 1;
                break;
            case 'h':
                print_help();
                break;
            case 'V':
                print_version();
                break;
            case 'g':
                generate_config();
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                print_help();
                exit(EXIT_FAILURE);
        }
    }
}

// Function to check if the given URL or IP is in the blacklist
int is_blacklisted(Config *config, const char *hostname) {
    for (int i = 0; i < config->black_list_count; i++) {
        if (strstr(hostname, config->black_list[i]) != NULL) {
            return 1; // Blacklisted
        }
    }
    return 0; // Not blacklisted
}

// Function to check if the client IP is in the allowed hosts list
int is_allowed_host(Config *config, const char *client_ip) {
    // If no specific allowed hosts are specified, allow all
    if (strcmp(config->allowed_hosts, "*") == 0) {
        return 1;
    }

    // Split allowed hosts by commas and check if client IP matches
    char allowed_hosts_copy[1024];
    strncpy(allowed_hosts_copy, config->allowed_hosts, sizeof(allowed_hosts_copy));
    char *token = strtok(allowed_hosts_copy, ",");
    while (token != NULL) {
        if (strcmp(token, client_ip) == 0) {
            return 1; // Allowed host
        }
        token = strtok(NULL, ",");
    }

    return 0; // Not allowed
}

// Function to log requests in the desired format
void log_request(const char *client_ip, const char *method, const char *url, const char *protocol,
                 const char *user_agent, const char *referer, int status_code, int content_length) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%d/%b/%Y:%H:%M:%S %z", tm_info);

    // Log format:
    // 172.17.0.1 - - [06/Aug/2024:14:55:37 +0000] "GET / HTTP/1.1" 200 615 "-" "Mozilla/5.0"
    printf("%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
           client_ip, time_str, method, url, protocol, status_code, content_length, referer ? referer : "-", user_agent);
}

// Function for processing HTTPS (CONNECT method)
void handle_https(int client_socket, const char *hostname, int port) {
    int server_socket;
    struct sockaddr_in server_addr;

    // Create a new socket connection for the target server
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error creating server socket for HTTPS");
        close(client_socket);
        return;
    }

    // Set up target server address
    struct hostent *server = gethostbyname(hostname);
    if (server == NULL) {
        perror("Error resolving target host for HTTPS");
        close(client_socket);
        close(server_socket);
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    // Establishing a connection to the target server
    if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error connecting to target server for HTTPS");
        close(client_socket);
        close(server_socket);
        return;
    }

    // Send a response to the client that the connection has been established
    const char *connection_established = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(client_socket, connection_established, strlen(connection_established), 0);

    // Forwarding data between client and server
    fd_set fdset;
    char buffer[BUFFER_SIZE];
    int max_fd = (client_socket > server_socket ? client_socket : server_socket) + 1;

    while (1) {
        FD_ZERO(&fdset);
        FD_SET(client_socket, &fdset);
        FD_SET(server_socket, &fdset);

        // Waiting for activity on client or server
        int activity = select(max_fd, &fdset, NULL, NULL, NULL);
        if (activity < 0) {
            perror("Error on select()");
            break;
        }

        // Forwarding data from the client to the server
        if (FD_ISSET(client_socket, &fdset)) {
            int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) break;
            send(server_socket, buffer, bytes_received, 0);
        }

        // Forward data from the server to the client
        if (FD_ISSET(server_socket, &fdset)) {
            int bytes_received = recv(server_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) break;
            send(client_socket, buffer, bytes_received, 0);
        }
    }

    close(server_socket);
    close(client_socket);
}

// Function to handle the connection between client and server
void handle_connection(int client_socket, Config *config, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Get the client's IP address
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

    // Check if the client's IP is allowed
    if (!is_allowed_host(config, client_ip)) {
        if (config->verbose) {
            printf("Blocked: The IP %s is not allowed to access the proxy.\n", client_ip);
        }
        const char *blocked_response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        send(client_socket, blocked_response, strlen(blocked_response), 0);
        close(client_socket);
        return;
    }

    // Receive data from the client
    bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
    if (bytes_received <= 0) {
        if (config->verbose) {
            printf("Error receiving data from the client.\n");
        }
        close(client_socket);
        return;
    }

    // Parse the request to extract the method, URL, and protocol
    char method[10], url[256], protocol[10];
    sscanf(buffer, "%s %s %s", method, url, protocol);

    // Extract relevant headers (User-Agent, Referer, etc.)
    char user_agent[256] = "-", referer[256] = "-";
    char *user_agent_ptr = strstr(buffer, "User-Agent:");
    char *referer_ptr = strstr(buffer, "Referer:");

    if (user_agent_ptr) {
        sscanf(user_agent_ptr, "User-Agent: %[^\r\n]", user_agent);
    }

    if (referer_ptr) {
        sscanf(referer_ptr, "Referer: %[^\r\n]", referer);
    }

    // If verbose is enabled, print the details of the request
    if (config->verbose) {
        printf("\n[Incoming connection] Client IP: %s\n", client_ip);
        printf("Requested Method: %s, URL: %s, Protocol: %s\n", method, url, protocol);
        printf("User-Agent: %s\n", user_agent);
        printf("Referer: %s\n", referer);
    }

    // Check if the URL or hostname is blacklisted
    char hostname[256];
    sscanf(url, "http://%[^/]", hostname);

    if (is_blacklisted(config, hostname)) {
        if (config->verbose) {
            printf("Blocked: The URL or IP %s is blacklisted.\n", hostname);
        }
        const char *blocked_response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        send(client_socket, blocked_response, strlen(blocked_response), 0);
        close(client_socket);
        return;
    }

    // Check if it's an HTTPS connection (CONNECT method)
    if (strcmp(method, "CONNECT") == 0) {
        char hostname[256];
        int port = 443; // Default HTTPS port

        // Parse the hostname and port from the URL (hostname:port)
        sscanf(url, "%[^:]:%d", hostname, &port);

        if (config->verbose) {
            printf("Handling HTTPS request to %s on port %d\n", hostname, port);
        }

        // Handle the HTTPS connection
        handle_https(client_socket, hostname, port);
        return;
    }

    // Connect to the target HTTP server
    struct hostent *server;
    struct sockaddr_in server_addr;

    server = gethostbyname(hostname);
    if (server == NULL) {
        if (config->verbose) {
            printf("Error: Target host not found.\n");
        }
        close(client_socket);
        return;
    }

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        if (config->verbose) {
            printf("Error creating server socket.\n");
        }
        close(client_socket);
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);  // HTTP port
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        if (config->verbose) {
            printf("Error connecting to the server %s.\n", hostname);
        }
        close(client_socket);
        close(server_socket);
        return;
    }

    if (config->verbose) {
        char server_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(server_addr.sin_addr), server_ip, INET_ADDRSTRLEN);
        printf("Connection established to target server %s (IP: %s, Port: 80).\n", hostname, server_ip);
    }

    // Forward the request to the target server
    send(server_socket, buffer, bytes_received, 0);

    // Receive the response from the server and forward it to the client
    int total_bytes_sent = 0;
    while ((bytes_received = recv(server_socket, buffer, sizeof(buffer), 0)) > 0) {
        send(client_socket, buffer, bytes_received, 0);
        total_bytes_sent += bytes_received;
    }

    // Log the request in the desired format
    log_request(client_ip, method, url, protocol, user_agent, referer, 200, total_bytes_sent);

    if (config->verbose) {
        printf("Connection to client IP %s, Port %d closed.\n", client_ip, ntohs(client_addr.sin_port));
    }

    close(server_socket);
    close(client_socket);
}

// Function to be executed by each new thread
void *thread_func(void *args) {
    ThreadArgs *thread_args = (ThreadArgs *)args;
    handle_connection(thread_args->client_socket, thread_args->config, thread_args->client_addr);
    free(thread_args);  // Free memory
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    int proxy_socket, client_socket;
    struct sockaddr_in proxy_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    Config config;

    // Default configuration values (fallback variables)
    strcpy(config.listen_ip, FALLBACK_LISTEN_IP);
    config.port = FALLBACK_PORT;
    strcpy(config.allowed_hosts, FALLBACK_ALLOWED_HOSTS);
    config.black_list_count = 0;  // Initialize the blacklist count
    config.verbose = 0;

    // Load the configuration file (optional)
    load_config_file(&config);

    // Parse command-line arguments
    parse_arguments(argc, argv, &config);

    // Check for root permissions if necessary
    check_root_permissions(config.port);

    // Create the proxy socket
    proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_socket < 0) {
        perror("Error creating proxy socket");
        exit(1);
    }

    // Set socket options to reuse the address (fixes "Address already in use" issue)
    int optval = 1;
    if (setsockopt(proxy_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("Error setting SO_REUSEADDR option");
        close(proxy_socket);
        exit(1);
    }

    // Configure the proxy address
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = inet_addr(config.listen_ip);
    proxy_addr.sin_port = htons(config.port);

    // Bind the proxy socket to the IP and port
    if (bind(proxy_socket, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("Error binding proxy socket");
        close(proxy_socket);
        exit(1);
    }

    // Listen for incoming connections
    if (listen(proxy_socket, 10) < 0) {
        perror("Error listening for connections");
        close(proxy_socket);
        exit(1);
    }

    printf("Proxy running on IP %s, Port %d...\n", config.listen_ip, config.port);

    // Main loop to handle incoming connections
    while (1) {
        client_socket = accept(proxy_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Error accepting connection");
            continue;
        }

        // Create thread arguments
        ThreadArgs *args = malloc(sizeof(ThreadArgs));
        args->client_socket = client_socket;
        args->config = &config;
        args->client_addr = client_addr;

        // Create a new thread to handle the connection
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, thread_func, (void *)args) != 0) {
            perror("Error creating thread");
            close(client_socket);
            free(args);
        } else {
            pthread_detach(thread_id);  // Automatically clean up thread
        }
    }

    close(proxy_socket);
    return 0;
}
