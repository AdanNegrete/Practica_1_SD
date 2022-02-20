#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SERVER_ADDRESS	"192.168.0.9" /* IP del servidor */
#define PORT		5050		/* Puerto de conexión */

char dir_ip[12]="";
char puerto[10]="";
char buf_tx[30]="Hola, soy el cliente."; 	/* Texto de prueba */
char buf_rx[30]="";				/* Texto de recepción */

int main(){
	
	printf("\nIngrese la IP del servidor: ");
	gets(dir_ip);
	printf("\nIngrese el puerto del servidor: ");
	gets(puerto);
	
	
	int sockfd;
	int bandera=0;
	struct sockaddr_in servidor;
	
	while(strcmp(buf_tx,"Adios.")){
	
		/* Creación de Socket */
		sockfd = socket(AF_INET, SOCK_STREAM,0);
		if(sockfd == -1){
			printf("[CLIENTE]: Fallo la creacion del socket. \n");
			return -1;
		}else{
			if(bandera==0){
				printf("[CLIENTE]: Socket creado correctamente. \n");
				printf("Conexión al servidor exitosa...\n");
				bandera=1;
			}
		}
		
		memset(&servidor,0,sizeof(servidor));
		
		/* Inicializando la estructura del servidor */
		servidor.sin_family 		= AF_INET;
		servidor.sin_addr.s_addr	= inet_addr(dir_ip);
		servidor.sin_port 		= htons(atoi(puerto));
		
		
		
		/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
		/* Código de programa */
		
		/* Intento de conexión al servidor */
		if(connect(sockfd, (struct sockaddr*)&servidor, sizeof(servidor))!=0){
			printf("Conexion al servidor fallida...\n");
			return -1;
		}
		
		read(sockfd, buf_rx, sizeof(buf_rx));
		printf("\n[Servidor]: %s \n",buf_rx);
		
		memset(&buf_rx,'\0',sizeof(buf_rx));
		memset(&buf_tx,'\0',sizeof(buf_tx));
		
		printf("\nIngrese un mensaje para el servidor: ");
		gets(buf_tx);
		write(sockfd, buf_tx, sizeof(buf_tx));
		
		/* Cerrando el socket */
		close(sockfd);
		
	}	
	
	/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

}
