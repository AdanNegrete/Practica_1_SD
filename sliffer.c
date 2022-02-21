#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netinet/in.h>

#include <signal.h>
#include <errno.h>

#define MAX_BUFFER 	2000

int main(){

	int sockfd; /*Descriptor de socket*/
	int size_addr;
	unsigned char buffer[MAX_BUFFER];
	
	struct sockaddr_in servidor, cliente; /* Estructura de socket */
	struct sockaddr saddr; /* Estructura de paquete */
	
	size_addr=sizeof(saddr);
	
	/* creación del socket */
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); 
	if(sockfd == -1){	
		fprintf(stderr, "Error: No se abrió el socket. %d: %s \n",errno, strerror(errno));
		return -1;
	}else{
		printf("Sliffer: Socket creado\n");
	}
	
	/* Volviendo promiscua mi red :O */
	struct ifreq ethreq;
	strncpy(ethreq.ifr_name,"enp0s3",IFNAMSIZ);
	ioctl(sockfd,SIOCGIFFLAGS,&ethreq);
	ethreq.ifr_flags |= IFF_PROMISC;
	if(ioctl(sockfd,SIOCSIFFLAGS,&ethreq)<0){
		printf("\nNo se pudo configurar el modo promiscuo :(\n");
	}else{
		printf("\nSe configuró el modo promiscuo");
	}
	
	int len;
	int cont=200;
	
	while(cont>0){
		
		memset(&buffer,0, sizeof(buffer));
		
		len=recvfrom(sockfd, buffer, MAX_BUFFER, 0,&saddr, &size_addr);
		
		struct ethhdr *chefsito;
		
		if(len == 0)
			printf("\nNo re recivió mensaje \n");
		
		if(len < 0){
			fprintf(stderr, "Error: Mensaje no leído. %d: %s \n",errno, strerror(errno));
		}else{
			chefsito=(struct ethhdr*)buffer;
			printf("\nDestino: %d:%d:%d:%d:%d:%d \n",chefsito->h_dest[0],chefsito->h_dest[1],chefsito->h_dest[2],chefsito->h_dest[3],chefsito->h_dest[4],chefsito->h_dest[4],chefsito->h_dest[5]);
			
			printf("\nOrigen: %d:%d:%d:%d:%d:%d \n",chefsito->h_source[0],chefsito->h_source[1],chefsito->h_source[2],chefsito->h_source[3],chefsito->h_source[4],chefsito->h_source[4],chefsito->h_source[5]);
			
			printf("\nTipo: %d \n",chefsito->h_proto);
			
			printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
			
		}
		cont-=1;	
	}
	system("/sbin/ifconfig enp0s3 -promisc");
	
}
