#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

/*Testing macros*/
//#define TEST_CLIENT_1 0
//#define TEST_CLIENT_2 0
//#define TEST_CLIENT_3a 0
//#define TEST_CLIENT_3b 0
//#define TEST_CLIENT_5 0

#define TEST_SERVER_3a 0


#ifdef TEST_CLIENT_3b
const char* SERVER_CERT_FILE = "server_test_client_3b.pem";
#else
const char* SERVER_CERT_FILE = "bob.pem";
#endif

#ifdef TEST_SERVER_3a
const char* CA_FILE = "test_server_3a_ca.pem";
#else
const char* CA_FILE = "568ca.pem";
#endif

#ifdef TEST_CLIENT_2
const char* CIPHER_LIST = "DES";
#else
const char* CIPHER_LIST = "TLSv1:SSLv2:SSLv3";
#endif

const char* PASSWORD = "password";


void close_connection(SSL* ssl, int sock){
    int ret = SSL_shutdown(ssl);
    
    if(!ret){
        shutdown(sock,1);
        ret = SSL_shutdown(ssl);
    }
    
    if(ret!=1){
        printf(FMT_INCOMPLETE_CLOSE);
    }
    close(sock);
}

int main(int argc, char **argv) {
    int s, sock, port = PORT;
    struct sockaddr_in sin;
    int val = 1;
    pid_t pid;

    /*Parse command line arguments*/

    switch (argc) {
        case 1:
            break;
        case 2:
            port = atoi(argv[1]);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "invalid port number");
                exit(0);
            }
            break;
        default:
            printf("Usage: %s port\n", argv[0]);
            exit(0);
    }

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        close(sock);
        exit(0);
    }


    /*SSL setup*/
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

#ifdef TEST_CLIENT_1
    SSL_CTX* ctx = SSL_CTX_new(SSLv2_server_method());
#else
    /*Create the SSL context*/
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_server_method());
#endif
    
    if (ctx == NULL) {
        perror("Unable to create the context");
        return 1;
    }

    /*Set up the cipher list*/
    SSL_CTX_set_cipher_list(ctx, CIPHER_LIST);

    /*Load the client certificate*/
    if (SSL_CTX_use_certificate_chain_file(ctx, SERVER_CERT_FILE) != 1) {
        printf("Unable to load the certificate\n");
        return 2;
    }

    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) != 1) {
        printf("Unable to load CA certificate\n");
        return 2;
    }
    
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*)PASSWORD);
    
    SSL_CTX_use_PrivateKey_file(ctx,SERVER_CERT_FILE,SSL_FILETYPE_PEM);
    
    /*Make sure the server request client certificates*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    memset(&sin, 0, sizeof (sin));
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof (val));

    if (bind(sock, (struct sockaddr *) &sin, sizeof (sin)) < 0) {
        perror("bind");
        close(sock);
        exit(0);
    }

    if (listen(sock, 5) < 0) {
        perror("listen");
        close(sock);
        exit(0);
    }

    while (1) {

        if ((s = accept(sock, NULL, 0)) < 0) {
            perror("accept");
            close(sock);
            close(s);
            exit(0);
        }

        /*fork a child to handle the connection*/

        if ((pid = fork())) {
            close(s);
        } else {
            /*Child code*/
            
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, s);
            //BIO* sbio = BIO_new_socket(s, BIO_CLOSE);
            //SSL_set_bio(ssl, sbio, sbio);
            
            int result = SSL_accept(ssl);
            if(result != 1 ){
                printf(FMT_ACCEPT_ERR);
                ERR_print_errors_fp(stdout);
                return 1;
            }
            
            int len;
            char buf[256];
            char *answer = "42";

            len = SSL_read(ssl, &buf, 255);
            if(len <= 0){
                close_connection(ssl,s);
                close(sock);
                return 0;
            }
            buf[len] = '\0';
            printf(FMT_OUTPUT, buf, answer);
            
            
            SSL_write(ssl, answer, strlen(answer));

            close(sock);
            
#ifndef TEST_CLIENT_5
            close_connection(ssl,s);
#endif
            return 0;
        }
    }

    close(sock);
    return 1;
}
