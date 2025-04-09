# rproxy
rproxy - a very small and fast webproxy written in C

## Parameter

```bash
rproxy --help

Usage: rproxy [OPTIONS]
A simple multithreaded HTTP/HTTPS proxy server.

Options:
  -p, --port <port>          Specify the port to listen on (default: 8080)
  -l, --listen <ip>          Specify the IP address to listen on (default: 0.0.0.0)
  -a, --allowed-hosts <list> Comma-separated list of allowed hosts or IPs
  -b, --black-list <list>    Comma-separated list of blacklisted URLs, IPs, or IP ranges
  -B, --block-clients <list> Comma-separated list of client IPs or IP ranges to block
  -t, --timeout <seconds>    Set connection timeout in seconds (default: 30)
  -A, --auth                 Enable basic authentication
  -U, --username <user>      Set authentication username (default: admin)
  -P, --password <pass>      Set authentication password (default: password)
  -v, --verbose              Enable verbose output
  -g, --generate-config      Generate configuration file in ~/.rproxy.conf
  -h, --help                 Display this help message
  -V, --version              Display the program version
```

## Features

- Multithreaded proxy server with thread pool for better resource management
- Support for both HTTP and HTTPS connections
- Configurable allowed hosts and blacklist
- Client IP blocking with support for CIDR notation
- Connection timeout settings
- Basic authentication support
- Dynamic blacklist implementation
- Proper signal handling for clean shutdown
- Improved error handling with HTTP error responses
- Supported and tested Platforms: macOS, Linux

## Configuration File

rproxy can be configured using a configuration file located at `~/.rproxy.conf`. You can generate a default configuration file using:

```bash
rproxy --generate-config
```

The configuration file contains the following settings:

```
listen=0.0.0.0
port=8080
allowed_hosts=*
black_list=
client_blocklist=
timeout=30
auth_enabled=0
auth_user=admin
auth_pass=password
```

## Dependencies

rproxy depends on the following libraries:
- pthread (for multithreading)
- base64 (for authentication)

## Compiling and installing rproxy

To compile the C code and create a finished binary program, you can use a Makefile. This Makefile automates the compilation process and, if desired, also the installation of the program on your system.

### Explanation Makefile

- CC: The compiler, in this case gcc.
- CFLAGS: The flags for the compiler. -Wall activates all warnings, and -pthread adds the pthread library for multithreading support.
- LDFLAGS: Linker flags for additional libraries (like -lbase64).
- TARGET: The name of the generated binary program (in this case rproxy).
- SRCS: The source files (here only rproxy.c).
- OBJS: The object files that are automatically generated from the source files.
- all: The default target used when calling make to compile the program.
- install: Copies the binary program to /usr/local/bin so that it can be used system-wide.
- clean: Removes all generated object and binary files.
- uninstall: Removes the binary program from /usr/local/bin.

### Steps for compilation and installation

#### Compile

Navigate to the directory containing the C code and the Makefile and execute the following command to compile the program.

```bash
make
```
This will create an executable binary program called rproxy in the same directory.

##### Install (optional)

If you want to install the program system-wide (e.g. to /usr/local/bin), execute the following command.

```bash
sudo make install
```

This copies the program to /usr/local/bin (or where it was specified in the Makefile) so that you can call it from anywhere by simply entering rproxy in the command line.

##### Clean up

To remove the generated object files and the binary program from the directory, you can use the following command.

```bash
make clean
```

##### Uninstall (optional)

To remove the program from /usr/local/bin again, execute this command.

```bash
sudo make uninstall
```

##### After the installation

After the installation by `make install` you can simply run the program by typing `rproxy` in your terminal. You can use the parameters that you have implemented in the program, e.g.

```bash
rproxy -p 8080 -l 0.0.0.0 -v
```

If the program was only compiled by `make`, you can execute the program by entering `./rproxy`.

```bash
./rproxy -p 8080 -l 0.0.0.0 -v
```

## Examples

### Running with basic authentication
```bash
rproxy -A -U myuser -P mysecretpassword
```

### Setting a custom timeout
```bash
rproxy -t 60
```

### Using both blacklist and authentication
```bash
rproxy -b "facebook.com,twitter.com" -A -v
```

### Limiting access to specific client IPs
```bash
rproxy -a "192.168.1.10,192.168.1.11"
```

### Blocking specific client IPs
```bash
rproxy -B "192.168.1.100,10.0.0.0/8"
```

### Using domain wildcards in blacklist
```bash
rproxy -b "*.example.com,facebook.com"
```

## Blacklist and Blocking Features

### URL Blacklisting
The `-b` parameter accepts:
- Exact domains: `example.com`
- Wildcard domains: `*.example.com` (blocks all subdomains)
- Individual hostnames or IPs

### Client IP Blocking
The `-B` parameter accepts:
- Individual IP addresses: `192.168.1.100`
- CIDR notation for IP ranges: `10.0.0.0/8` (blocks entire subnets)

### Configuration File Examples

```
# Block specific websites
black_list=facebook.com,twitter.com,*.adult-site.com

# Block specific client IPs and ranges
client_blocklist=192.168.1.100,10.0.0.0/8
```

## Advanced Usage

### Using Both Blacklist and Client Blocking

You can combine different security features:

```bash
rproxy -a "192.168.1.0/24" -b "facebook.com,twitter.com" -B "10.0.0.0/8" -A -v
```

This example:
- Allows only clients from the 192.168.1.0/24 subnet to use the proxy
- Blocks access to facebook.com and twitter.com
- Blocks any clients from the 10.0.0.0/8 subnet
- Requires authentication
- Provides verbose output

### Proxy Logging

In verbose mode, rproxy logs connections in a format similar to standard web server logs:

```
172.17.0.1 - - [06/Apr/2025:14:55:37 +0000] "GET http://example.com/ HTTP/1.1" 200 615 "-" "Mozilla/5.0"
```
