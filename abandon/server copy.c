#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <ctype.h> // for isxdigit()
#include <netinet/tcp.h> // Add this line
#include <sys/sendfile.h> /* sendfile */
#include <sys/select.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>





#define errquit(m)	{ perror(m); exit(-1); }
#define BUFFER_SIZE 2097152

static int port_http = 80;
static int port_https = 443;
static const char *docroot = "/html";

int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            // Convert the two hexadecimal characters to a char value
            *dst++ = (hex_to_int(a) << 4) | hex_to_int(b);
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

void set_non_blocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) errquit("fcntl F_GETFL");
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        errquit("fcntl F_SETFL O_NONBLOCK");
        exit(0);
    }
}

const char *get_content_type(const char *path) {
    const char *last_dot = strrchr(path, '.');
    if (last_dot) { // Check the file extension and return the MIME type
        if (strcmp(last_dot, ".html") == 0) return "text/html";
        if (strcmp(last_dot, ".txt") == 0) return "text/plain";
        if (strcmp(last_dot, ".jpg") == 0) return "image/jpeg";
        if (strcmp(last_dot, ".png") == 0) return "image/png";
        if (strcmp(last_dot, ".mp3") == 0) return "audio/mp3";
        if (strcmp(last_dot, ".wav") == 0) return "audio/wav";
    }
    return "application/octet-stream";
}

void send_response_header(int client_socket, const char *status, const char *content_type, long content_length) 
{
    char header[1024];
    int header_length = snprintf(header, sizeof(header),
        "%s\r\n"
        "Content-Type: %s; charset=UTF-8\r\n"
        "Content-Length: %ld\r\n"
        "\r\n", 
        status, content_type, content_length);
    write(client_socket, header, header_length);
}

void send_file(int client_socket, const char *file_path) {
    int filefd = open(file_path, O_RDONLY);
    if (filefd < 0) {
        // If we fail to open the file, send a 404 Not Found header instead
        send_response_header(client_socket, "HTTP/1.0 404 Not Found", "text/html", strlen("<h1>404 Not Found</h1>"));
        write(client_socket, "<h1>404 Not Found</h1>", strlen("<h1>404 Not Found</h1>"));
        return;
    }

    // Get the file size
    struct stat file_stat;
    if (fstat(filefd, &file_stat) < 0) {
        perror("fstat");
        close(filefd);
        return;
    }

    // Send the HTTP header
    send_response_header(client_socket, "HTTP/1.0 200 OK", get_content_type(file_path), file_stat.st_size);

    // Send the file content
    char file_buffer[BUFFER_SIZE];
    int bytes_read;
    //sendfile(client_socket, filefd, 0, file_stat.st_size);
    while ((bytes_read = read(filefd, file_buffer, BUFFER_SIZE)) > 0) {
        write(client_socket, file_buffer, bytes_read);
    }

    close(filefd);
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "server.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
    //    ERR_print_errors_fp(stderr);
    //    exit(EXIT_FAILURE);
    //}
}

void send_response(int client_socket, const char *header, const char *filepath) 
{
    write(client_socket, header, strlen(header));

    if (filepath) 
	{
        int filefd = open(filepath, O_RDONLY);
        char file_buffer[BUFFER_SIZE];
        int bytes_read;

        while ((bytes_read = read(filefd, file_buffer, BUFFER_SIZE)) > 0) 
		{
            write(client_socket, file_buffer, bytes_read);
        }

        close(filefd);
    }
}

void send_301_redirect(int client_socket, const char *new_location) 
{
    char header[1024];
    int header_length = snprintf(header, sizeof(header),
        "HTTP/1.0 301 Moved Permanently\r\n"
        "Location: %s\r\n"
        "\r\n", 
        new_location);
    write(client_socket, header, header_length);
}

void* handle_request(int arg, SSL * ssl) 
{
	int client_socket = arg;
    //free(arg); // Free the memory allocated for the client socket pointer
    //set_non_blocking(client_socket);
    char buffer[BUFFER_SIZE];
    // Read the HTTP request from the client
    int bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    
	//if (bytes_read < 0) 
	//{
    //    perror("read");
    //    close(client_socket);
    //    pthread_exit(NULL);
    //}
    
    buffer[bytes_read] = '\0';
    char method[10], path[1024];
    sscanf(buffer, "%s %s", method, path);
	char decoded_path[1024];
    url_decode(decoded_path, path);
	if (strcasecmp(method, "GET") != 0) 
	{
        send_response_header(client_socket, "HTTP/1.0 501 Not Implemented", "text/html", strlen("<h1>501 Not Implemented</h1>"));
        write(client_socket, "<h1>501 Not Implemented</h1>", strlen("<h1>501 Not Implemented</h1>"));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
        return NULL;
    }
	char *query_string = strchr(decoded_path, '?');
    if (query_string) {
        *query_string = '\0'; // Terminate the path at the start of the query string
    }
    char full_path[2048];
    snprintf(full_path, sizeof(full_path), "%s%s", docroot, decoded_path);
	
    struct stat file_stat;
    //if (stat(full_path, &file_stat) < 0) {
    //    send_response(client_socket, "HTTP/1.0 404 Not Found\r\n\r\n", NULL);
    //    close(client_socket);
    //    return;
    //}
	int exists = stat(full_path, &file_stat);
    if (exists == 0 && S_ISDIR(file_stat.st_mode) && full_path[strlen(full_path) - 1] != '/') 
	{
        char redirect_path[2048];
        snprintf(redirect_path, sizeof(redirect_path), "HTTP/1.0 301 Moved Permanently\r\nLocation: %s/\r\n\r\n", path);
        write(client_socket, redirect_path, strlen(redirect_path));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
        return NULL;
    }
	
	else if (exists == 0 && S_ISDIR(file_stat.st_mode)) 
	{
        strncat(full_path, "index.html", sizeof(full_path) - strlen(full_path) - 1);
        if (stat(full_path, &file_stat) < 0) 
		{
            send_response_header(client_socket, "HTTP/1.0 403 Forbidden", "text/html", strlen("<h1>403 Forbidden</h1>"));
            write(client_socket, "<h1>403 Forbidden</h1>", strlen("<h1>403 Forbidden</h1>"));
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_socket);
            return NULL;
        }
    } 
    else if (exists < 0) 
    {
        send_response_header(client_socket, "HTTP/1.0 404 Not Found", "text/html", strlen("<h1>404 Not Found</h1>"));
        write(client_socket, "<h1>404 Not Found</h1>", strlen("<h1>404 Not Found</h1>"));
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
        return NULL;
    }
    if (S_ISREG(file_stat.st_mode)) {
        send_file(client_socket, full_path);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_socket);
        return NULL;
    }

    close(client_socket);
    SSL_shutdown(ssl);
    SSL_free(ssl);
	//pthread_exit(NULL);
    return NULL;
}

int main(int argc, char *argv[]) 
{
	int s;
	//return 0;
    int sock;
    SSL_CTX *ctx;

    /* Ignore broken pipe signals */
    //signal(SIGPIPE, SIG_IGN);

    ctx = create_context();

    configure_context(ctx);
	struct sockaddr_in sin;
	int  *client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
	if(argc > 1) { port_http  = strtol(argv[1], NULL, 0); }
	if(argc > 2) { if((docroot = strdup(argv[2])) == NULL) errquit("strdup"); }
	if(argc > 3) { port_https = strtol(argv[3], NULL, 0); }
    

	if((s = socket(PF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP)) < 0) errquit("socket");
    set_non_blocking(s);
    //fcntl(s, F_SETFL, O_NONBLOCK);
    //fcntl(s, F_SETFL, O_ASYNC);
    int bufsize = 1024 * 1024 * 2; 
    //if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0) {
    //    perror("setsockopt SO_RCVBUF failed");
    //    close(s);
    //    
    //}

    //if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
    //    perror("setsockopt SO_SNDBUF failed");
    //    close(s);
    //    
    //}

	do 
	{
		int v = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	} while(0);

	bzero(&sin, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port = htons(80);
	if(bind(s, (struct sockaddr*) &sin, sizeof(sin)) < 0) errquit("bind");
	if(listen(s, SOMAXCONN) < 0) errquit("listen");
	

	fd_set master_set, read_set;
    FD_ZERO(&master_set);
    FD_SET(s, &master_set);
    int max_fd = s;

    while (1) 
    {
        //printf("hit\n");
        SSL *ssl;
        read_set = master_set;
        if (select(max_fd + 1, &read_set, NULL, NULL, NULL) == -1) {
            errquit("select");
        }

        for (int i = 0; i <= max_fd; i++) {
            if (FD_ISSET(i, &read_set)) {
                if (i == s) {
                    // Handle new connections
                    struct sockaddr_in client_addr;
                    socklen_t addr_size = sizeof(client_addr);
                    int client_socket = accept(s, (struct sockaddr *)&client_addr, &addr_size);
                    if (client_socket == -1) {
                        perror("accept");
                        continue;
                    }
                    
                    FD_SET(client_socket, &master_set);
                    if (client_socket > max_fd) {
                        max_fd = client_socket;
                    }
                } else {
                    int client_socket = i;
                    ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, client_socket);
                    handle_request(client_socket, ssl);
                    FD_CLR(client_socket, &master_set);
                    //close(client_socket);
                }
            }
        }
    }
    SSL_CTX_free(ctx);
	return 0;
}
