#include <unistd.h>

/* librerias para sockets */
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

/* librerias de strings */
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* creación de parametros del servidor */

#define SERV_PORT	8080			//Puerto de conexión
#define SERV_ADDR	"192.168.0.109"	//IP del servidor
#define BUFFER_LN	1000			//Tamaño máximo de entrada y salida de datos del buffer
#define BACKLOG	2			//No Max de clientes

int main(){
	int sockfd, connfd;	/* descriptores de conexión del socket y del cliente */
	unsigned int len;	/* longitud de la dirección del cliente */
	struct sockaddr_in servidor, cliente; /* estructura de servidor y de cliente para crear el socjet */
	
	int len_rx, len_tx=0; /* longitud de mensajes enviados y revividos */
	char dir_ip[12]="";
	char puerto[10]="";
	char buff_tx[BUFFER_LN] = "Bienvenido, soy el servidor";
	char buff_rx[BUFFER_LN] = "H"; /* buffer de recepción */
	
	/* Inciailizando servidor */
	printf("\nIngrese la IP del servidor: ");
	gets(dir_ip);
	printf("\nIngrese el puerto del servidor: ");
	gets(puerto);
	
	//
	
	/* creación del socket */
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if(sockfd == -1){	
		fprintf(stderr, "[Server-error]: GG No Servidor. %d: %s \n",errno, strerror(errno));
		return -1;
	}else{
		printf("[Server]: EZ Socket\n");
	}
	
	/* Limpiando la estructura */
	memset(&servidor,0, sizeof(servidor));
	
	/* Inicializando estructura */
	servidor.sin_family		= AF_INET;
	servidor.sin_addr.s_addr	= inet_addr(dir_ip);
	servidor.sin_port		= htons(atoi(puerto));
	
	/* asignación de socket */
	if ((bind(sockfd, (struct sockaddr *)&servidor, sizeof(servidor))) != 0) {
		fprintf(stderr, "[Server-error]: Asignación de socket (bind) fallida. %d: %s \n",errno, strerror(errno));
		return -1;
	}else{
		printf("[Server]: Socket asignado\n");
	}
	
		/* Socket escuchando */
		if((listen(sockfd,BACKLOG))!=0){
			fprintf(stderr, "[Server-error]: Servidor no está escuchando. %d: %s \n",errno, strerror(errno));
			return -1;
		}else{
			printf("[Server]: Socket escuchando en el puerto: %d \n\n", ntohs(servidor.sin_port));
		}
		
		
		len = sizeof(cliente); /* Guardar el tamaño en bites de la estructura del cliente */
		
		/* Inicializando servidor */
		
		int numero=1,resultado;
		
	while(numero!=0){
	
		connfd = accept(sockfd, (struct sockaddr *)&cliente,&len);
		printf("Servidor iniciado, esperando cliente: \n");
		if(connfd < 0){
			fprintf(stderr, "[Server-error]: Conexion rechazada. %d: %s \n",errno, strerror(errno));
			return -1;
		}else{
			
				
			printf("Se conecto un cliente uwu\n");
			
			/* Leyendo datos del cliente al buffer */
			len_rx = read(connfd, buff_rx, sizeof(buff_rx));
			
			if(len_rx == -1){
				fprintf(stderr, "[Server-error]: Datos no leídos. %d: %s \n",errno, strerror(errno));
			}else if(len_rx==0){
				printf("[Server]: Conexión finalizada con el cliente \n\n");
				close(connfd);
				break;
			}else{
				/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
				/* Código del programa */
				
				printf("[Server]: El numero recibido es: %s \n", buff_rx);
				numero = atoi(buff_rx);
				//printf("Numerito= %i",numero);
				
				memset(&buff_rx,'\0',sizeof(buff_rx));
				memset(&buff_tx,'\0',sizeof(buff_tx));
				
				if(numero==0){
					sprintf(buff_tx,"%d",numero);
				}else{
					resultado = numero+1;
					sprintf(buff_tx,"%d",resultado);
				}
				
				write(connfd, buff_tx, strlen(buff_tx));
				
				/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
			}
			
		}
		
		close(connfd);
		
	}
	
	close(sockfd);
	
}

