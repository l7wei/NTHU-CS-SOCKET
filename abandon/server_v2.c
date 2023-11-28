#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

#define errquit(m)	{ perror(m); exit(-1); }
#define BUFFER_SIZE 1024

static int port_http = 80;
static int port_https = 443;
static const char *docroot = "/html";

const char *get_content_type(const char *path) {
    const char *last_dot = strrchr(path, '.');
    if (last_dot) { // Check the file extension and return the MIME type
        if (strcmp(last_dot, ".html") == 0) return "text/html";
        if (strcmp(last_dot, ".txt") == 0) return "text/plain";
        if (strcmp(last_dot, ".jpg") == 0) return "image/jpeg";
        if (strcmp(last_dot, ".png") == 0) return "image/png";
        // More MIME types can be added here
    }
    return "application/octet-stream"; // Default MIME type
}

void send_response_header(int client_socket, const char *status, const char *content_type, long content_length) 
{
    char header[1024];
    int header_length = snprintf(header, sizeof(header),
        "%s\r\n"
        "Content-Type: %s\r\n"
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
    while ((bytes_read = read(filefd, file_buffer, BUFFER_SIZE)) > 0) {
        write(client_socket, file_buffer, bytes_read);
    }

    close(filefd);
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

void handle_request(int client_socket) 
{
    char buffer[BUFFER_SIZE];
    int bytes_read;

    // Read the request
    bytes_read = read(client_socket, buffer, BUFFER_SIZE - 1);
    if (bytes_read < 0) {
        perror("read");
        return;
    }

    buffer[bytes_read] = '\0';

    // Parse HTTP request
    char method[10], path[1024];
    sscanf(buffer, "%s %s", method, path);
	if (strcmp(path, "/") == 0) 
	{
        strcpy(path, "/index.html");
    }
    // Determine the requested file path
    char full_path[2048];
    snprintf(full_path, sizeof(full_path), "%s%s", docroot, path);

    // Check if the file exists and is accessible
    struct stat file_stat;
    //if (stat(full_path, &file_stat) < 0) {
    //    send_response(client_socket, "HTTP/1.0 404 Not Found\r\n\r\n", NULL);
    //    close(client_socket);
    //    return;
    //}
	if (stat(full_path, &file_stat) < 0 || S_ISDIR(file_stat.st_mode)) 
	{
        // If file not found or is a directory, send a 404 Not Found response
        send_response_header(client_socket, "HTTP/1.0 404 Not Found", "text/html", strlen("<h1>404 Not Found</h1>"));
        write(client_socket, "<h1>404 Not Found</h1>", strlen("<h1>404 Not Found</h1>"));
		return;
    }

    // Create and send HTTP response
    if (S_ISDIR(file_stat.st_mode)) {
        send_response(client_socket, "HTTP/1.0 403 Forbidden\r\n\r\n", NULL);
    } else {
        send_file(client_socket, full_path);
    }

    close(client_socket);
}

int main(int argc, char *argv[]) 
{
	int s;
	struct sockaddr_in sin;

	if(argc > 1) { port_http  = strtol(argv[1], NULL, 0); }
	if(argc > 2) { if((docroot = strdup(argv[2])) == NULL) errquit("strdup"); }
	if(argc > 3) { port_https = strtol(argv[3], NULL, 0); }

	if((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) errquit("socket");

	do 
	{
		int v = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
	} while(0);

	bzero(&sin, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(80);
	if(bind(s, (struct sockaddr*) &sin, sizeof(sin)) < 0) errquit("bind");
	if(listen(s, SOMAXCONN) < 0) errquit("listen");

	do 
	{
		int c;
		struct sockaddr_in csin;
		socklen_t csinlen = sizeof(csin);

		if((c = accept(s, (struct sockaddr*) &csin, &csinlen)) < 0) {
			perror("accept");
			continue;
		}

		handle_request(c);
	} while(1);

	return 0;
}
