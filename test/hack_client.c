#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/*Headers for ssl*/
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#define HOST "localhost"
#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

/*Testing macros*/
#define TEST_SERVER_3b 0
//#define TEST_SERVER_6  0

const char* CLIENT_CERT_FILE = "alice.pem";
const char* CA_FILE = "568ca.pem";

const char* PASSWORD = "password";

const char* CIPHER_LIST = "SHA1";

const char* SERVER_COMMON_NAME = "Bob's Server";
const char* SERVER_EMAIL_ADDRESS = "ece568bob@ecf.utoronto.ca";

void close_connection(SSL* ssl, int sock){
    int ret = SSL_shutdown(ssl);
    
    if(!ret){
        shutdown(sock,1);
        ret = SSL_shutdown(ssl);
    }
    
    if(ret!=1){
        printf(FMT_INCORRECT_CLOSE);
    }
    close(sock);
}

int main(int argc, char **argv) {
    int len, sock, port = PORT;
    char *host = HOST;
    struct sockaddr_in addr;
    struct hostent *host_entry;
    char buf[256];
    char *secret = "What's the question?";

    /*Parse command line arguments*/

    switch (argc) {
        case 1:
            break;
        case 3:
            host = argv[1];
            port = atoi(argv[2]);
            if (port < 1 || port > 65535) {
                fprintf(stderr, "invalid port number");
                exit(0);
            }
            break;
        default:
            printf("Usage: %s server port\n", argv[0]);
            exit(0);
    }

    /*get ip address of the host*/

    host_entry = gethostbyname(host);

    if (!host_entry) {
        fprintf(stderr, "Couldn't resolve host");
        exit(0);
    }

    memset(&addr, 0, sizeof (addr));
    addr.sin_addr = *(struct in_addr *) host_entry->h_addr_list[0];
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr), port);

    /*open socket*/

    if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        perror("socket");
    if (connect(sock, (struct sockaddr *) &addr, sizeof (addr)) < 0)
        perror("connect");

    /*SSL setup*/
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_crypto_strings();


    /*Create the SSL context*/
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());

    if (ctx == NULL) {
        perror("Unable to create the context");
        return 1;
    }

    /*Remove the SSLv2 from the option*/
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void*) PASSWORD);

    SSL_CTX_use_PrivateKey_file(ctx, CLIENT_CERT_FILE, SSL_FILETYPE_PEM);

    SSL_CTX_set_cipher_list(ctx, CIPHER_LIST);

#ifndef TEST_SERVER_3b
    /*Load the client certificate*/
    if (SSL_CTX_use_certificate_chain_file(ctx, CLIENT_CERT_FILE) != 1) {
        printf("Unable to load the certificate\n");
    }
#endif

    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) != 1) {
        printf("Unable to load CA certificate\n");
    }

    /*Initialize the ssl socket*/
    SSL* ssl = SSL_new(ctx);
    BIO* sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    /*Connect (Handshake)*/
    int result = SSL_connect(ssl);
    if (result != 1) {
        //printf("%d\n",result);
        printf(FMT_CONNECT_ERR);
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    char serverName[256];
    char serverEmail[256];
    char CaName[256];

    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        printf(FMT_NO_VERIFY);
        close_connection(ssl,sock);
        exit(1);
    }

    /*Grab the certificate of the server*/
    X509* pcert = SSL_get_peer_certificate(ssl);

    if (pcert == NULL) {
        printf("Unable to get the peer certificate\n");
        close_connection(ssl,sock);
        exit(1);
    }

    /*Check the common name in the certificate*/
    X509_NAME* subjectName = X509_get_subject_name(pcert);

    X509_NAME_get_text_by_NID(subjectName, NID_commonName, serverName, sizeof (serverName));

    if (strcmp(serverName, SERVER_COMMON_NAME) != 0) {
        perror(FMT_CN_MISMATCH);
       close_connection(ssl,sock);
       exit(1);
    }

    /*Check the email address in the certificate*/
    X509_NAME_get_text_by_NID(subjectName, NID_pkcs9_emailAddress, serverEmail, sizeof (serverEmail));

    if (strcmp(serverEmail, SERVER_EMAIL_ADDRESS) != 0) {
        perror(FMT_EMAIL_MISMATCH);
        close_connection(ssl,sock);
        exit(1);
    }

    X509_NAME* issuerName = X509_get_issuer_name(pcert);
    X509_NAME_get_text_by_NID(issuerName, NID_commonName, CaName, sizeof (CaName));
    
    printf(FMT_SERVER_INFO, serverName, serverEmail, CaName);

    len = SSL_write(ssl, secret, strlen(secret));
    /*
    if (len < 0) {
        printf("Send has failed");
    }
     */
    len = SSL_read(ssl, &buf, 255);
    /*
    if (len < 0) {
        perror("Receive fail");
    }
     */
    buf[len] = '\0';

    /* this is how you output something for the marker to pick up */
    printf(FMT_OUTPUT, secret, buf);

#ifndef TEST_SERVER_6
    close_connection(ssl,sock);
#endif
    //close(sock);
    return 1;
}
