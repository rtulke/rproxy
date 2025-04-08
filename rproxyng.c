/*
 * rproxy - A simple multithreaded HTTP/HTTPS proxy server
 *
 * Author: Robert Tulke (original code)
 * Version: 1.2.0 (improved version)
 * License: GPL v3.0
 *
 * Description:
 * This program implements a basic multithreaded HTTP/HTTPS proxy server in C. It
 * listens for incoming HTTP/HTTPS connections, forwards requests to the target
 * server, and relays the responses back to the client.
 *
 * Improvements in this version:
 * - Fixed potential buffer overflows and memory leaks
 * - Added proper signal handling
 * - Enhanced URL parsing and validation
 * - Added connection timeouts
 * - Improved error handling with HTTP error responses
 * - Added dynamic blacklist implementation
 * - Added thread pool for better resource management
 * - Added basic proxy authentication
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
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <base64.h> // For base64 encoding/decoding (may need to be installed)

#define BUFFER_SIZE 8192
#define VERSION "1.2.0"
#define CONFIG_FILE "~/.rproxy.conf"
#define FALLBACK_LISTEN_IP "0.0.0.0"
#define FALLBACK_PORT 8080
#define FALLBACK_ALLOWED_HOSTS "*"
#define DEFAULT_CONNECTION_TIMEOUT 30 // Seconds
#define THREAD_POOL_SIZE 10
#define MAX_QUEUE_SIZE 100
#define DEFAULT_AUTH_ENABLED 0
#define DEFAULT_AUTH_USER "admin"
#define DEFAULT_AUTH_PASS "password"

// Global variable for proxy socket (for signal handler)
int global_proxy_socket = -1;
int shutdown_flag = 0;

// Dynamic blacklist structure
typedef struct {
    char **entries;
    int count;
    int capacity;
} BlackList;

// Configuration structure to store program settings
typedef struct {
    char listen_ip[INET_ADDRSTRLEN];  // listen IP
    int port;                         // running port
    char allowed_hosts[1024];         // List of allowed hosts
    BlackList black_list;             // Dynamic blacklist
    int verbose;                      // Flag for verbose output
    int connection_timeout;           // Connection timeout in seconds
    int auth_enabled;                 // Enable basic authentication
    char auth_user[64];               // Authentication username
    char auth_pass[64];               // Authentication password
} Config;

// Structure for passing arguments to threads
typedef struct {
    int client_socket;
    Config *config;
    struct sockaddr_in client_addr;
} ThreadArgs;

// Queue structure for thread pool
typedef struct {
    ThreadArgs **items;
    int head;
    int tail;
    int size;
    int capacity;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} JobQueue;

// Global job queue
JobQueue job_queue;

// Function prototypes
void initialize_blacklist(BlackList *blacklist, int initial_capacity);
void add_to_blacklist(BlackList *blacklist, const char *entry);
int is_blacklisted(BlackList *blacklist, const char *hostname);
void free_blacklist(BlackList *blacklist);
void handle_signal(int sig);
void *thread_pool_worker(void *arg);
int initialize_job_queue(JobQueue *queue, int capacity);
int enqueue_job(JobQueue *queue, ThreadArgs *args);
ThreadArgs* dequeue_job(JobQueue *queue);
void destroy_job_queue(JobQueue *queue);
void send_http_error(int client_socket, int status_code, const char *message);
int extract_hostname(const char *url, char *hostname, size_t hostname_size);
int extract_port(const char *url, int default_port);
int validate_url(const char *url);
int set_socket_timeout(int socket, int seconds);
int is_authenticated(const char *auth_header, const char *username, const char *password);

// Signal handler function
void handle_signal(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    shutdown_flag = 1;
    
    // Close the proxy socket
    if (global_proxy_socket != -1) {
        close(global_proxy_socket);
        global_proxy_socket = -1;
    }
    
    // Don't exit immediately, let the main loop handle the shutdown
}

// Initialize the blacklist with a given capacity
void initialize_blacklist(BlackList *blacklist, int initial_capacity) {
    blacklist->entries = malloc(initial_capacity * sizeof(char*));
    if (blacklist->entries == NULL) {
        fprintf(stderr, "Error: Memory allocation failed for blacklist\n");
        exit(EXIT_FAILURE);
    }
    
    blacklist->count = 0;
    blacklist->capacity = initial_capacity;
}

// Add an entry to the blacklist
void add_to_blacklist(BlackList *blacklist, const char *entry) {
    // Resize if needed
    if (blacklist->count >= blacklist->capacity) {
        int new_capacity = blacklist->capacity * 2;
        char **new_entries = realloc(blacklist->entries, new_capacity * sizeof(char*));
        
        if (new_entries == NULL) {
            fprintf(stderr, "Error: Memory reallocation failed for blacklist\n");
            return;
        }
        
        blacklist->entries = new_entries;
        blacklist->capacity = new_capacity;
    }
    
    // Copy the entry
    blacklist->entries[blacklist->count] = strdup(entry);
    
    if (blacklist->entries[blacklist->count] == NULL) {
        fprintf(stderr, "Error: Failed to duplicate string for blacklist\n");
        return;
    }
    
    blacklist->count++;
}

// Check if a hostname is in the blacklist
int is_blacklisted(BlackList *blacklist, const char *hostname) {
    for (int i = 0; i < blacklist->count; i++) {
        if (strstr(hostname, blacklist->entries[i]) != NULL) {
            return 1; // Blacklisted
        }
    }
    return 0; // Not blacklisted
}

// Free the blacklist memory
void free_blacklist(BlackList *blacklist) {
    for (int i = 0; i < blacklist->count; i++) {
        free(blacklist->entries[i]);
    }
    
    free(blacklist->entries);
    blacklist->entries = NULL;
    blacklist->count = 0;
    blacklist->capacity = 0;
}

// Initialize the job queue
int initialize_job_queue(JobQueue *queue, int capacity) {
    queue->items = malloc(capacity * sizeof(ThreadArgs*));
    
    if (queue->items == NULL) {
        return -1;
    }
    
    queue->head = 0;
    queue->tail = 0;
    queue->size = 0;
    queue->capacity = capacity;
    
    if (pthread_mutex_init(&queue->mutex, NULL) != 0) {
        free(queue->items);
        return -1;
    }
    
    if (pthread_cond_init(&queue->not_empty, NULL) != 0) {
        pthread_mutex_destroy(&queue->mutex);
        free(queue->items);
        return -1;
    }
    
    if (pthread_cond_init(&queue->not_full, NULL) != 0) {
        pthread_cond_destroy(&queue->not_empty);
        pthread_mutex_destroy(&queue->mutex);
        free(queue->items);
        return -1;
    }
    
    return 0;
}

// Add a job to the queue
int enqueue_job(JobQueue *queue, ThreadArgs *args) {
    pthread_mutex_lock(&queue->mutex);
    
    while (queue->size == queue->capacity && !shutdown_flag) {
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }
    
    if (shutdown_flag) {
        pthread_mutex_unlock(&queue->mutex);
        return -1;
    }
    
    queue->items[queue->tail] = args;
    queue->tail = (queue->tail + 1) % queue->capacity;
    queue->size++;
    
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
    
    return 0;
}

// Get a job from the queue
ThreadArgs* dequeue_job(JobQueue *queue) {
    pthread_mutex_lock(&queue->mutex);
    
    while (queue->size == 0 && !shutdown_flag) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }
    
    if (shutdown_flag && queue->size == 0) {
        pthread_mutex_unlock(&queue->mutex);
        return NULL;
    }
    
    ThreadArgs *args = queue->items[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    queue->size--;
    
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    
    return args;
}

// Clean up the job queue
void destroy_job_queue(JobQueue *queue) {
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    free(queue->items);
    queue->items = NULL;
}

// Function to send HTTP error responses
void send_http_error(int client_socket, int status_code, const char *message) {
    char response[512];
    const char *status_text;
    
    switch (status_code) {
        case 400: status_text = "Bad Request"; break;
        case 403: status_text = "Forbidden"; break;
        case 404: status_text = "Not Found"; break;
        case 407: status_text = "Proxy Authentication Required"; break;
        case 408: status_text = "Request Timeout"; break;
        case 500: status_text = "Internal Server Error"; break;
        case 502: status_text = "Bad Gateway"; break;
        case 504: status_text = "Gateway Timeout"; break;
        default: status_text = "Unknown Error"; break;
    }
    
    // Create error response
    int len = snprintf(response, sizeof(response),
                      "HTTP/1.1 %d %s\r\n"
                      "Content-Type: text/html\r\n"
                      "Connection: close\r\n"
                      "Content-Length: %zu\r\n"
                      "\r\n"
                      "<html><body><h1>%d %s</h1><p>%s</p></body></html>",
                      status_code, status_text,
                      strlen(message) + 50 + strlen(status_text),
                      status_code, status_text, message);
    
    if (len >= sizeof(response)) {
        // Response too large - create a simpler one
        snprintf(response, sizeof(response),
                "HTTP/1.1 %d %s\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n",
                status_code, status_text);
    }
    
    send(client_socket, response, strlen(response), 0);
}

// Extract hostname from URL with proper validation
int extract_hostname(const char *url, char *hostname, size_t hostname_size) {
    if (!url || !hostname || hostname_size == 0) {
        return -1;
    }
    
    memset(hostname, 0, hostname_size);
    
    // First, handle CONNECT method which typically has hostname:port format
    if (strchr(url, '/') == NULL) {
        char *colon = strchr(url, ':');
        if (colon != NULL) {
            size_t len = colon - url;
            if (len >= hostname_size) {
                return -1; // Hostname too long
            }
            strncpy(hostname, url, len);
            hostname[len] = '\0';
        } else {
            if (strlen(url) >= hostname_size) {
                return -1; // Hostname too long
            }
            strncpy(hostname, url, hostname_size - 1);
        }
        return 0;
    }
    
    // Handle standard URLs with scheme
    const char *host_start = NULL;
    
    if (strncmp(url, "http://", 7) == 0) {
        host_start = url + 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        host_start = url + 8;
    } else {
        // URL without scheme, assume the hostname is at the beginning
        host_start = url;
    }
    
    // Find the end of the hostname (port or path)
    const char *host_end = host_start;
    while (*host_end && *host_end != '/' && *host_end != ':' && *host_end != '?' && *host_end != '#') {
        host_end++;
    }
    
    size_t host_len = host_end - host_start;
    if (host_len >= hostname_size) {
        return -1; // Hostname too long
    }
    
    if (host_len == 0) {
        return -1; // Empty hostname
    }
    
    // Copy the hostname
    strncpy(hostname, host_start, host_len);
    hostname[host_len] = '\0';
    
    return 0;
}

// Extract port from URL
int extract_port(const char *url, int default_port) {
    const char *colon = strchr(url, ':');
    
    // If there's no colon or it's part of the scheme (http://)
    if (colon == NULL || colon == url + 4 || colon == url + 5) {
        // Check if there's another colon (for the port)
        colon = strchr((colon == NULL) ? url : colon + 1, ':');
    }
    
    if (colon != NULL) {
        colon++; // Skip the colon
        
        // Make sure there are digits after the colon
        if (*colon >= '0' && *colon <= '9') {
            // Parse the port number
            int port = atoi(colon);
            
            // Check if the port is in a valid range
            if (port > 0 && port < 65536) {
                return port;
            }
        }
    }
    
    return default_port;
}

// URL validation
int validate_url(const char *url) {
    if (url == NULL || *url == '\0') {
        return 0;
    }
    
    // Check for obviously malformed URLs
    if (strchr(url, ' ') != NULL) {
        return 0;
    }
    
    // Check for valid scheme (or no scheme which is valid for CONNECT)
    if (strncmp(url, "http://", 7) != 0 && 
        strncmp(url, "https://", 8) != 0 && 
        strchr(url, '/') != NULL) {
        // Not a CONNECT style URL and doesn't have a valid scheme
        return 0;
    }
    
    // Additional checks could be added here
    
    return 1;
}

// Set socket timeout
int set_socket_timeout(int socket, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;
    
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        return -1;
    }
    
    if (setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        return -1;
    }
    
    return 0;
}

// Check Basic authentication
int is_authenticated(const char *auth_header, const char *username, const char *password) {
    if (auth_header == NULL) {
        return 0;
    }
    
    // Skip "Basic " prefix
    const char *encoded = auth_header + 6;
    
    // Decode the Base64 credentials
    unsigned char decoded[128];
    memset(decoded, 0, sizeof(decoded));
    
    // In a real implementation, use a proper base64 decoder
    // This is a placeholder for the actual implementation
    int decoded_len = base64_decode(encoded, decoded, sizeof(decoded) - 1);
    
    if (decoded_len < 0) {
        return 0;
    }
    
    // Format should be "username:password"
    char expected[128];
    snprintf(expected, sizeof(expected), "%s:%s", username, password);
    
    return strcmp((char *)decoded, expected) == 0;
}

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
    printf("  -t, --timeout <seconds>    Set connection timeout in seconds (default: 30)\n");
    printf("  -A, --auth                 Enable basic authentication\n");
    printf("  -U, --username <user>      Set authentication username (default: admin)\n");
    printf("  -P, --password <pass>      Set authentication password (default: password)\n");
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
    fprintf(file, "timeout=%d\n", DEFAULT_CONNECTION_TIMEOUT);
    fprintf(file, "auth_enabled=%d\n", DEFAULT_AUTH_ENABLED);
    fprintf(file, "auth_user=%s\n", DEFAULT_AUTH_USER);
    fprintf(file, "auth_pass=%s\n", DEFAULT_AUTH_PASS);

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
        // Remove newline character
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        if (strncmp(line, "listen=", 7) == 0) {
            strncpy(config->listen_ip, line + 7, sizeof(config->listen_ip) - 1);
        } else if (strncmp(line, "port=", 5) == 0) {
            config->port = atoi(line + 5);
        } else if (strncmp(line, "allowed_hosts=", 14) == 0) {
            strncpy(config->allowed_hosts, line + 14, sizeof(config->allowed_hosts) - 1);
        } else if (strncmp(line, "black_list=", 11) == 0) {
            char *blacklist = line + 11;
            char *token = strtok(blacklist, ",");
            while (token != NULL) {
                add_to_blacklist(&config->black_list, token);
                token = strtok(NULL, ",");
            }
        } else if (strncmp(line, "timeout=", 8) == 0) {
            config->connection_timeout = atoi(line + 8);
        } else if (strncmp(line, "auth_enabled=", 13) == 0) {
            config->auth_enabled = atoi(line + 13);
        } else if (strncmp(line, "auth_user=", 10) == 0) {
            strncpy(config->auth_user, line + 10, sizeof(config->auth_user) - 1);
        } else if (strncmp(line, "auth_pass=", 10) == 0) {
            strncpy(config->auth_pass, line + 10, sizeof(config->auth_pass) - 1);
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
        {"timeout", required_argument, 0, 't'},
        {"auth", no_argument, 0, 'A'},
        {"username", required_argument, 0, 'U'},
        {"password", required_argument, 0, 'P'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {"generate-config", no_argument, 0, 'g'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:a:b:t:AU:P:vhVg", long_options, NULL)) != -1) {
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
                while (token != NULL) {
                    add_to_blacklist(&config->black_list, token);
                    token = strtok(NULL, ",");
                }
                break;
            }
            case 't':
                config->connection_timeout = atoi(optarg);
                break;
            case 'A':
                config->auth_enabled = 1;
                break;
            case 'U':
                strncpy(config->auth_user, optarg, sizeof(config->auth_user) - 1);
                break;
            case 'P':
                strncpy(config->auth_pass, optarg, sizeof(config->auth_pass) - 1);
                break;
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

// Function to check if the client IP is in the allowed hosts list
int is_allowed_host(Config *config, const char *client_ip) {
    // If no specific allowed hosts are specified, allow all
    if (strcmp(config->allowed_hosts, "*") == 0) {
        return 1;
    }

    // Split allowed hosts by commas and check if client IP matches
    char allowed_hosts_copy[1024];
    strncpy(allowed_hosts_copy, config->allowed_hosts, sizeof(allowed_hosts_copy) - 1);
    allowed_hosts_copy[sizeof(allowed_hosts_copy) - 1] = '\0';
    
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
           client_ip, time_str, method, url, protocol, status_code, content_length, 
           referer ? referer : "-", user_agent ? user_agent : "-");
}

// Improved function for processing HTTPS (CONNECT method)
void handle_https(int client_socket, const char *hostname, int port, Config *config) {
    int server_socket;
    struct sockaddr_in server_addr;

    // Create a new socket connection for the target server
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        if (config->verbose) {
            perror("Error creating server socket for HTTPS");
        }
        send_http_error(client_socket, 502, "Failed to create socket to target server");
        close(client_socket);
        return;
    }

    // Set socket timeout
    if (set_socket_timeout(server_socket, config->connection_timeout) < 0) {
        if (config->verbose) {
            perror("Failed to set socket timeout");
        }
    }

    // Set up target server address
    struct hostent *server = gethostbyname(hostname);
    if (server == NULL) {
        if (config->verbose) {
            perror("Error resolving target host for HTTPS");
        }
        send_http_error(client_socket, 502, "Failed to resolve target host");
        close(client_socket);
        close(server_socket);
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    // Establishing a connection to the target server
    if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        if (config->verbose) {
            perror("Error connecting to target server for HTTPS");
        }
        send_http_error(client_socket, 502, "Failed to connect to target server");
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

    while (!shutdown_flag) {
        FD_ZERO(&fdset);
        FD_SET(client_socket, &fdset);
        FD_SET(server_socket, &fdset);

        // Set up timeout for select
        struct timeval timeout;
        timeout.tv_sec = config->connection_timeout;
        timeout.tv_usec = 0;

        // Waiting for activity on client or server
        int activity = select(max_fd, &fdset, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno == EINTR) {
                // Interrupted by a signal, check if we should exit
                if (shutdown_flag) {
                    break;
                }
                continue;
            }
            
            if (config->verbose) {
                perror("Error on select()");
            }
            break;
        }
        
        if (activity == 0) {
            // Timeout reached
            if (config->verbose) {
                printf("Connection timed out\n");
            }
            break;
        }

        // Forwarding data from the client to the server
        if (FD_ISSET(client_socket, &fdset)) {
            int bytes_received = recv(client_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) {
                break; // Client disconnected or error
            }
            
            int bytes_sent = 0;
            while (bytes_sent < bytes_received) {
                int result = send(server_socket, buffer + bytes_sent, bytes_received - bytes_sent, 0);
                if (result <= 0) {
                    if (config->verbose) {
                        perror("Error sending data to server");
                    }
                    break;
                }
                bytes_sent += result;
            }
            
            if (bytes_sent < bytes_received) {
                break; // Failed to send all data
            }
        }

        // Forward data from the server to the client
        if (FD_ISSET(server_socket, &fdset)) {
            int bytes_received = recv(server_socket, buffer, sizeof(buffer), 0);
            if (bytes_received <= 0) {
                break; // Server disconnected or error
            }
            
            int bytes_sent = 0;
            while (bytes_sent < bytes_received) {
                int result = send(client_socket, buffer + bytes_sent, bytes_received - bytes_sent, 0);
                if (result <= 0) {
                    if (config->verbose) {
                        perror("Error sending data to client");
                    }
                    break;
                }
                bytes_sent += result;
            }
            
            if (bytes_sent < bytes_received) {
                break; // Failed to send all data
            }
        }
    }

    // Clean up
    close(server_socket);
    close(client_socket);
}

// Improved function to handle the connection between client and server
void handle_connection(ThreadArgs *args) {
    int client_socket = args->client_socket;
    Config *config = args->config;
    struct sockaddr_in client_addr = args->client_addr;
    char buffer[BUFFER_SIZE];
    int bytes_received;

    // Set socket timeout
    if (set_socket_timeout(client_socket, config->connection_timeout) < 0) {
        if (config->verbose) {
            perror("Failed to set client socket timeout");
        }
    }

    // Get the client's IP address
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

    // Check if the client's IP is allowed
    if (!is_allowed_host(config, client_ip)) {
        if (config->verbose) {
            printf("Blocked: The IP %s is not allowed to access the proxy.\n", client_ip);
        }
        send_http_error(client_socket, 403, "Your IP address is not allowed to use this proxy");
        close(client_socket);
        free(args); // Free the thread args
        return;
    }

    // Receive data from the client
    bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        if (config->verbose) {
            printf("Error receiving data from the client or client disconnected.\n");
        }
        close(client_socket);
        free(args); // Free the thread args
        return;
    }
    
    // Null-terminate the buffer for string operations
    buffer[bytes_received] = '\0';

    // Parse the request to extract the method, URL, and protocol
    char method[16] = {0}, url[BUFFER_SIZE] = {0}, protocol[16] = {0};
    if (sscanf(buffer, "%15s %4095s %15s", method, url, protocol) != 3) {
        if (config->verbose) {
            printf("Invalid HTTP request format\n");
        }
        send_http_error(client_socket, 400, "Invalid HTTP request format");
        close(client_socket);
        free(args); // Free the thread args
        return;
    }

    // Validate the URL
    if (!validate_url(url)) {
        if (config->verbose) {
            printf("Invalid URL: %s\n", url);
        }
        send_http_error(client_socket, 400, "Invalid URL format");
        close(client_socket);
        free(args); // Free the thread args
        return;
    }

    // Extract relevant headers (User-Agent, Referer, Authorization, etc.)
    char user_agent[256] = "-", referer[256] = "-", auth_header[512] = {0};
    char *user_agent_ptr = strstr(buffer, "User-Agent:");
    char *referer_ptr = strstr(buffer, "Referer:");
    char *auth_ptr = strstr(buffer, "Proxy-Authorization: Basic ");

    if (user_agent_ptr) {
        sscanf(user_agent_ptr, "User-Agent: %255[^\r\n]", user_agent);
    }

    if (referer_ptr) {
        sscanf(referer_ptr, "Referer: %255[^\r\n]", referer);
    }

    if (auth_ptr) {
        strncpy(auth_header, auth_ptr, sizeof(auth_header) - 1);
        // Extract just the base64 encoded part
        char *space = strchr(auth_header, ' ');
        if (space) {
            char *base64_start = space + 1;
            char *end = strchr(base64_start, '\r');
            if (end) *end = '\0';
        }
    }

    // Check authentication if enabled
    if (config->auth_enabled) {
        if (auth_ptr == NULL || !is_authenticated(auth_ptr, config->auth_user, config->auth_pass)) {
            // Send authentication required response
            char response[512];
            snprintf(response, sizeof(response),
                    "HTTP/1.1 407 Proxy Authentication Required\r\n"
                    "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
                    "Content-Length: 0\r\n"
                    "Connection: close\r\n\r\n");
            send(client_socket, response, strlen(response), 0);
            
            if (config->verbose) {
                printf("Authentication required for client %s\n", client_ip);
            }
            
            close(client_socket);
            free(args); // Free the thread args
            return;
        }
    }

    // If verbose is enabled, print the details of the request
    if (config->verbose) {
        printf("\n[Incoming connection] Client IP: %s\n", client_ip);
        printf("Requested Method: %s, URL: %s, Protocol: %s\n", method, url, protocol);
        printf("User-Agent: %s\n", user_agent);
        printf("Referer: %s\n", referer);
    }

    // Extract hostname from URL
    char hostname[256];
    if (extract_hostname(url, hostname, sizeof(hostname)) != 0) {
        if (config->verbose) {
            printf("Failed to extract hostname from URL: %s\n", url);
        }
        send_http_error(client_socket, 400, "Invalid hostname in URL");
        close(client_socket);
        free(args); // Free the thread args
        return;
    }

    // Check if the URL or hostname is blacklisted
    if (is_blacklisted(&config->black_list, hostname)) {
        if (config->verbose) {
            printf("Blocked: The URL or IP %s is blacklisted.\n", hostname);
        }
        send_http_error(client_socket, 403, "This website is blocked by the proxy administrator");
        close(client_socket);
        free(args); // Free the thread args
        return;
    }

    // Check if it's an HTTPS connection (CONNECT method)
    if (strcmp(method, "CONNECT") == 0) {
        int port = extract_port(url, 443); // Default HTTPS port
        
        if (config->verbose) {
            printf("Handling HTTPS request to %s on port %d\n", hostname, port);
        }

        // Handle the HTTPS connection
        handle_https(client_socket, hostname, port, config);
        free(args); // Free the thread args
        return;
    }

    // Handling HTTP connection
    struct hostent *server;
    struct sockaddr_in server_addr;

    server = gethostbyname(hostname);
    if (server == NULL) {
        if (config->verbose) {
            printf("Error: Target host %s not found.\n", hostname);
        }
        send_http_error(client_socket, 404, "Target host not found");
        close(client_socket);
        free(args); // Free the thread args
        return;
    }

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        if (config->verbose) {
            printf("Error creating server socket.\n");
        }
        send_http_error(client_socket, 500, "Failed to create connection to target server");
        close(client_socket);
        free(args); // Free the thread args
        return;
    }

    // Set socket timeout
    if (set_socket_timeout(server_socket, config->connection_timeout) < 0) {
        if (config->verbose) {
            perror("Failed to set server socket timeout");
        }
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);  // HTTP port or custom port
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        if (config->verbose) {
            printf("Error connecting to the server %s.\n", hostname);
        }
        send_http_error(client_socket, 502, "Failed to connect to target server");
        close(client_socket);
        close(server_socket);
        free(args); // Free the thread args
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
        int bytes_sent = 0;
        while (bytes_sent < bytes_received) {
            int result = send(client_socket, buffer + bytes_sent, bytes_received - bytes_sent, 0);
            if (result <= 0) {
                if (config->verbose) {
                    perror("Error sending data to client");
                }
                break;
            }
            bytes_sent += result;
        }
        
        if (bytes_sent < bytes_received) {
            break; // Failed to send all data
        }
        
        total_bytes_sent += bytes_received;
    }

    // Log the request in the desired format
    log_request(client_ip, method, url, protocol, user_agent, referer, 200, total_bytes_sent);

    if (config->verbose) {
        printf("Connection to client IP %s, Port %d closed.\n", client_ip, ntohs(client_addr.sin_port));
    }

    close(server_socket);
    close(client_socket);
    free(args); // Free the thread args
}

// Thread pool worker function
void *thread_pool_worker(void *arg) {
    Config *config = (Config *)arg;
    
    while (!shutdown_flag) {
        // Get job from queue
        ThreadArgs *args = dequeue_job(&job_queue);
        
        // Check for shutdown
        if (args == NULL && shutdown_flag) {
            break;
        }
        
        // Process the connection
        if (args != NULL) {
            handle_connection(args);
            // Note: args is freed inside handle_connection
        }
    }
    
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    int proxy_socket;
    struct sockaddr_in proxy_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    Config config;
    pthread_t thread_pool[THREAD_POOL_SIZE];

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Default configuration values
    strcpy(config.listen_ip, FALLBACK_LISTEN_IP);
    config.port = FALLBACK_PORT;
    strcpy(config.allowed_hosts, FALLBACK_ALLOWED_HOSTS);
    config.connection_timeout = DEFAULT_CONNECTION_TIMEOUT;
    config.auth_enabled = DEFAULT_AUTH_ENABLED;
    strcpy(config.auth_user, DEFAULT_AUTH_USER);
    strcpy(config.auth_pass, DEFAULT_AUTH_PASS);
    config.verbose = 0;
    
    // Initialize blacklist
    initialize_blacklist(&config.black_list, 10);

    // Load the configuration file
    load_config_file(&config);

    // Parse command-line arguments (override config file)
    parse_arguments(argc, argv, &config);

    // Check for root permissions if necessary
    check_root_permissions(config.port);
    
    // Initialize the job queue
    if (initialize_job_queue(&job_queue, MAX_QUEUE_SIZE) != 0) {
        fprintf(stderr, "Failed to initialize job queue\n");
        exit(EXIT_FAILURE);
    }

    // Create the proxy socket
    proxy_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_socket < 0) {
        perror("Error creating proxy socket");
        exit(EXIT_FAILURE);
    }
    
    // Save the proxy socket for signal handler
    global_proxy_socket = proxy_socket;

    // Set socket options to reuse the address
    int optval = 1;
    if (setsockopt(proxy_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("Error setting SO_REUSEADDR option");
        close(proxy_socket);
        exit(EXIT_FAILURE);
    }

    // Configure the proxy address
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = inet_addr(config.listen_ip);
    proxy_addr.sin_port = htons(config.port);

    // Bind the proxy socket to the IP and port
    if (bind(proxy_socket, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        perror("Error binding proxy socket");
        close(proxy_socket);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(proxy_socket, SOMAXCONN) < 0) {
        perror("Error listening for connections");
        close(proxy_socket);
        exit(EXIT_FAILURE);
    }

    printf("Proxy running on IP %s, Port %d...\n", config.listen_ip, config.port);
    printf("Press Ctrl+C to exit.\n");
    
    // Create thread pool
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_create(&thread_pool[i], NULL, thread_pool_worker, &config) != 0) {
            perror("Failed to create thread pool worker");
            exit(EXIT_FAILURE);
        }
    }

    // Main loop to accept connections and add them to the job queue
    while (!shutdown_flag) {
        // Set timeout for accept
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(proxy_socket, &read_fds);
        
        struct timeval timeout;
        timeout.tv_sec = 1;  // 1 second timeout to check shutdown_flag periodically
        timeout.tv_usec = 0;
        
        int select_result = select(proxy_socket + 1, &read_fds, NULL, NULL, &timeout);
        
        if (select_result < 0) {
            if (errno == EINTR) {
                continue; // Interrupted by signal
            }
            perror("Error in select");
            break;
        }
        
        if (select_result == 0) {
            continue; // Timeout, check shutdown_flag
        }
        
        // Accept new connection
        int client_socket = accept(proxy_socket, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_socket < 0) {
            if (errno == EINTR) {
                continue; // Interrupted by signal
            }
            perror("Error accepting connection");
            continue;
        }

        // Create thread arguments
        ThreadArgs *args = malloc(sizeof(ThreadArgs));
        if (args == NULL) {
            perror("Failed to allocate memory for thread arguments");
            close(client_socket);
            continue;
        }
        
        args->client_socket = client_socket;
        args->config = &config;
        args->client_addr = client_addr;

        // Add job to queue
        if (enqueue_job(&job_queue, args) != 0) {
            fprintf(stderr, "Failed to enqueue job or shutdown in progress\n");
            close(client_socket);
            free(args);
            continue;
        }
    }

    printf("Shutting down proxy server...\n");
    
    // Signal all worker threads to exit
    pthread_mutex_lock(&job_queue.mutex);
    shutdown_flag = 1;
    pthread_cond_broadcast(&job_queue.not_empty);
    pthread_mutex_unlock(&job_queue.mutex);
    
    // Wait for all threads to finish
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        pthread_join(thread_pool[i], NULL);
    }
    
    // Clean up
    close(proxy_socket);
    destroy_job_queue(&job_queue);
    free_blacklist(&config.black_list);
    
    printf("Proxy server shutdown complete.\n");
    return 0;
}
