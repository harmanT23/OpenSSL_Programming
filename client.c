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
#include <openssl/objects.h>
#include <openssl/err.h>

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

/*Master Client cert, CA cert*/
#define CLIENT_CERT "alice.pem"
#define CERT_AUTH "568ca.pem"
#define CLIENT_CIPHERS "SHA1"


/*Verification of Server*/
#define SERVER_CN "Bob's Server"
#define ISSUER_CN "ECE568 Certificate Authority"
#define SERVER_EMAIL "ece568bob@ecf.utoronto.ca"


/* Global PARAMS*/
BIO *net = NULL;
SSL *ssl = NULL;
int sock;

// SSL lib initiate
void init_openssl(void) {
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
}

//Verify Certificate Email
char* check_email(X509_NAME* name, char* valid_email) {
	int valid_email_len = strlen(valid_email) + 1;	
	char *peer_email = malloc(valid_email_len);

	// Get email
	X509_NAME_get_text_by_NID(name, NID_pkcs9_emailAddress, peer_email, valid_email_len);
	
	// Verify is its a valid email
	if(strcmp(peer_email, valid_email) != 0) {
		printf(FMT_EMAIL_MISMATCH);
		return NULL;
	}
	
	return peer_email;
}

//Verify Certificate Name
char* check_CN(X509_NAME* name, char* valid_cn) {
	int valid_cn_len = strlen(valid_cn) + 1;	
	char *cn = malloc(valid_cn_len);

	// Get CN
	X509_NAME_get_text_by_NID(name, NID_commonName, cn, valid_cn_len);
	
	// Verify is its a valid CN
	if(strcmp(cn, valid_cn) != 0) {
		printf(FMT_CN_MISMATCH);
		return NULL;
	}
	
	return cn;
}

//Authenticate Server
int check_cert(SSL* ssl) {
	
	// Get peer certificate
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    X509_NAME* subject = peer_cert ? X509_get_subject_name(peer_cert):NULL;
	X509_NAME* issuer = peer_cert ? X509_get_issuer_name(peer_cert):NULL;
		
	// Get CNs and email
    char* server_CN = check_CN(subject, SERVER_CN);
	if(server_CN == NULL) { return 0; }
	
	char* server_email = check_email(subject, SERVER_EMAIL);	
	if(server_email == NULL) { return 0; }

	//Get issuer name - Assume max name length is 256 chars
	char cert_issuer[256];
	X509_NAME_get_text_by_NID(issuer, NID_commonName, cert_issuer, 256);
	
	printf(FMT_SERVER_INFO, server_CN, server_email, cert_issuer);
	
	return 1;
}

int main(int argc, char **argv)
{
  /****************SSL PARAMS**************************/
  init_openssl();
  const SSL_METHOD* method = SSLv23_method();
  SSL_CTX* ctx = SSL_CTX_new(method);
  if(!ctx) {printf("Cannote create Context Obj\n");}
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);// No SSL_v2
  /*****************************************************/
  
  /***************SSL SET Client Key and CA*****************************/
  //Load Client Certificate
  if (SSL_CTX_use_certificate_chain_file(ctx, CLIENT_CERT) != 1)
  {
	  printf("Failed to set certificate chain file\n");
  }
  
  SSL_CTX_set_default_passwd_cb(ctx, (void*)"password"); //default password
  
  if (SSL_CTX_use_PrivateKey_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) != 1)
  {
	  printf("Failed to set Client Cert's private key\n");
  }
  
  //Load certificate authority
  if (SSL_CTX_load_verify_locations(ctx, CERT_AUTH, NULL) != 1)
  {
	  printf("Failed to set Certificate Authority's Cert\n");
  }
  /*********************************************************************/
  
 /*******************SET CLIENT SUPPORTED CIPHERS*********************/
 SSL_CTX_set_cipher_list(ctx, CLIENT_CIPHERS);
 /********************************************************************/
  
  /**********************Client SOCKET CONSTRUCTION******************/
  int len, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  int success_code;
  
  /*Parse command line arguments*/
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /**********************ACTIVE CLIENT SOCKET****************************/
  
  /*open socket*/
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  

  // Set BIO and ssl
  net = BIO_new_socket(sock, BIO_NOCLOSE);
  if(net <= 0) { printf("Binding SSL to socket failed\n"); }
  
  ssl = SSL_new(ctx);
  if(ssl <= 0){ printf("Cannot construct SSL obj from context\n"); }
  
  SSL_set_bio(ssl, net, net);

  // Connect SSL
  if(SSL_connect(ssl) != 1) { 
	  printf(FMT_CONNECT_ERR);
	  ERR_print_errors_fp(stderr);
	  SSL_shutdown(ssl);
	  SSL_free(ssl);
	  close(sock);
	  return 0;
 }

  //Determine if Server Certificate is valid
  success_code = SSL_get_verify_result(ssl);
  if(success_code != 0) {
	  printf(FMT_NO_VERIFY);
	  SSL_shutdown(ssl);
	  SSL_free(ssl);
	  close(sock);
	  return 0;
  }
  
  //Authenticate Server credential
  if(check_cert(ssl) != 1)
  {
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(sock);
	return 0;
  }
  
  // Send message
  int code = SSL_write(ssl, secret, strlen(secret)); 
  if(code <= 0) { 
	  printf(FMT_INCORRECT_CLOSE);
	  SSL_shutdown(ssl);
	  SSL_free(ssl);
	  close(sock);
	  return 0;
  }

  len = SSL_read(ssl, &buf, 255);
  if (len <= 0) {
	  printf(FMT_INCORRECT_CLOSE);
	  SSL_shutdown(ssl);
	  SSL_free(ssl);
	  close(sock);
	  return 0;
  }
  
  buf[len]= '\0';
  /**********************************/
  
  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);
  
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sock);
  return 1;
}
