# rproxy
roberts proxy - a very small and fast webproxy written in c

# Parameter

```bash
rproxy --help
No configuration file found at /root/.rproxy.conf. Using fallback variables.
Usage: rproxy [OPTIONS]
A simple multithreaded HTTP/HTTPS proxy server.

Options:
  -p, --port <port>          Specify the port to listen on (default: 8080)
  -l, --listen <ip>          Specify the IP address to listen on (default: 0.0.0.0)
  -a, --allowed-hosts <list> Comma-separated list of allowed hosts or IPs
  -b, --black-list <list>    Comma-separated list of blacklisted URLs, IPs, or IP ranges
  -v, --verbose              Enable verbose output
  -g, --generate-config      Generate configuration file in ~/.rproxy.conf
  -h, --help                 Display this help message
  -V, --version              Display the program version
```

# Compiling and installing rproxy

To compile the C code and create a finished binary program, you can use a Makefile. This Makefile automates the compilation process and, if desired, also the installation of the program on your system.

## Steps

## Explanation Makefile

- CC: The compiler, in this case gcc.
- CFLAGS: The flags for the compiler. -Wall activates all warnings, and -pthread adds the pthread library for multithreading support.
- TARGET: The name of the generated binary program (in this case rproxy).
- SRCS: The source files (here only rproxy.c).
- OBJS: The object files that are automatically generated from the source files.
- all: The default target used when calling make to compile the program.
- install: Copies the binary program to /usr/local/bin so that it can be used system-wide.
- clean: Removes all generated object and binary files.
- uninstall: Removes the binary program from /usr/local/bin.

## Steps for compilation and installation

### Compile

Navigate to the directory containing the C code and the Makefile and execute the following command to compile the program.

```bash
make
```
This will create an executable binary program called rproxy in the same directory.

### Install (optional)

If you want to install the program system-wide (e.g. to /usr/local/bin), execute the following command.

```bash
sudo make install
```

This copies the program to /usr/local/bin (or where it was specified in the Makefile) so that you can call it from anywhere by simply entering rproxy in the command line.

### Clean up

To remove the generated object files and the binary program from the directory, you can use the following command.

```bash
make clean
```

### Uninstall (optional)

To remove the program from /usr/local/bin again, execute this command.

```bash
sudo make uninstall
```

### After the installation

After the installation by `make install` you can simply run the program by typing `rproxy` in your terminal. You can use the parameters that you have implemented in the program, e.g.

```bash
rproxy -p 8080 -l 0.0.0.0 -v
```

If the program was only compiled by `make`, you can execute the program by entering `./rproxy`.

```bash
./rproxy -p 8080 -l 0.0.0.0 -v
```
