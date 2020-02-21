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
#include <openssl/objects.h>

#define PORT 8765

/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_ACCEPT_ERR_NOLINE "ECE568-SERVER: SSL accept error"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

/*Supported ciphers, server certificate and CA cert*/
#define SERVER_CIPHERS "SSLv2:SSLv3:TLSv1"
#define SERVER_CERT "bob.pem"
#define CERT_AUTH "568ca.pem"

// Initialize SSL Lib
void init_SSL(void)
{
  SSL_library_init();                      //init ssl
  SSL_load_error_strings();                //init error string
  ERR_load_crypto_strings();
}

// Print peer name and email
void print_peer_cred(SSL* ssl)
{
   char peer_email[256];
   char peer_name[256];
   
   // Get peer certificate
   X509 *peer_cert = SSL_get_peer_certificate(ssl);
   X509_NAME* sname = peer_cert ? X509_get_subject_name(peer_cert):NULL;

   if (sname != NULL)
   {
	   X509_NAME_get_text_by_NID(sname, NID_pkcs9_emailAddress, peer_email, 256);
	   X509_NAME_get_text_by_NID(sname, NID_commonName, peer_name, 256);
   }
   
   int idx = 0;
   while (idx < strlen(peer_name)) 
   {
	   if (peer_name[idx++] == '/')
	   {
		   peer_name[idx-1] = '\0';
		   break;
	   }
   }

   printf(FMT_CLIENT_INFO, peer_name, peer_email);
}

int main(int argc, char **argv)
{
  /****************SSL PARAMS**************************/
  init_SSL();
  const SSL_METHOD * method = SSLv23_server_method();
  SSL_CTX * ctx; //Context object
  /*****************************************************/
  
  /***************SSL SET Server Key and CA*****************************/
  ctx = SSL_CTX_new(method);
  if(!ctx) {printf("Cannote create Context Obj\n");}
  
  //Load Server Certificate
  if (SSL_CTX_use_certificate_chain_file(ctx, SERVER_CERT) != 1)
  {
	  printf("Failed to set certificate chain file\n");
  }
  
  SSL_CTX_set_default_passwd_cb(ctx, (void*)"password"); //default password
  
  if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) != 1)
  {
	  printf("Failed to set Server Cert's private key\n");
  }
  
  //Load certificate authority
  if (SSL_CTX_load_verify_locations(ctx, CERT_AUTH, NULL) != 1)
  {
	  printf("Failed to set Certificate Authority's Cert\n");
  }
 
  //Require that PEER send their certificate 
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
  
 /*********************************************************************/

 /*******************SET SERVER SUPPORTED CIPHERS*********************/
 SSL_CTX_set_cipher_list(ctx, SERVER_CIPHERS);
 /********************************************************************/
	
  /**********************SERVER SOCKET CONSTRUCTION******************/
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);

  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  /****************** ACTIVE SERVER ***************************/
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    if((pid=fork())){
      close(s);
    }
	
    else {
      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";
	  BIO *net = NULL;
	  SSL* ssl = NULL;
	  
	  /*Connect the above socket to SSL socket*/
	  net = BIO_new_socket(s, BIO_NOCLOSE);
	  if(net <= 0) { printf("Binding SSL to socket failed\n"); }
	  
	  ssl = SSL_new(ctx);
	  if(ssl <= 0){ printf("Cannot construct SSL obj from context\n"); }
	  
	  SSL_set_bio(ssl, net, net);
	  
	  ERR_clear_error(); //Only care about errors relating to OpenSSL handshake.

	  // SSL Accept logic
	  int code = SSL_accept(ssl);
	  
	  if (code == 0) {
		  printf(FMT_INCOMPLETE_CLOSE);
		  ERR_print_errors_fp(stderr);
		  SSL_shutdown(ssl);
		  SSL_free(ssl);
		  close(s);
		  exit(0);
	  }
	  
	  if (code < 0) {
		  printf(FMT_ACCEPT_ERR);
		  ERR_print_errors_fp(stderr);
		  SSL_shutdown(ssl);
		  SSL_free(ssl);
		  close(s);
		  exit(0);
	  }
	  /****************************************/
	  
	  print_peer_cred(ssl); //Print peer email and name
	  
	  // SSL Read 
	  len = SSL_read(ssl, &buf, 255);
	  if(len <= 0) {
		printf(FMT_INCOMPLETE_CLOSE);
	    SSL_shutdown(ssl);
	    SSL_free(ssl);
	    close(s);
	    exit(0);
	  }
	  
	  buf[len]= '\0';
	  printf(FMT_OUTPUT, buf, answer);
	 
	  // SSL Write
	  code = SSL_write(ssl, answer, strlen(answer));
	  if(code <= 0) { 
		  printf(FMT_INCOMPLETE_CLOSE);
		  SSL_shutdown(ssl);
		  SSL_free(ssl);
		  close(s);
		  exit(0);
	  }	
	  
	  SSL_shutdown(ssl);
	  SSL_free(ssl);
      close(s);
      return 1;
    }
  }
  
  close(sock);
  return 1;
}
