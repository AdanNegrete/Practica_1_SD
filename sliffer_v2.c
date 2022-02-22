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
#include <pthread.h>
#include <fcntl.h>

#define MAX_BUFFER 	2000

typedef struct packet{
	int num_pk;
	int len;
	unsigned char buffer[MAX_BUFFER];
}Pack;

int len; /* Longitud de paquetes */

void *analiza(void *argumento);

int main(){
	
	/* Variables */
	int cont;
	int sockfd; /*Descriptor de socket*/
	int size_addr; /*Tamaño de la estructura paquete*/
	char adapter[15]="";
	char packets[15]="";
	
	Pack paquete;
	
	pthread_t hilo_anz;
	
	
	/* Solicitud de datos */
	printf("\nIngrese el adaptador de red: ");
	gets(adapter);
	printf("\nIngrese el número: ");
	gets(packets);
	
	cont=atoi(packets);
	
	/* Configuración de socket */
	struct sockaddr saddr; /* Estructura de paquete */
	
	size_addr=sizeof(saddr); /* Tamaño de estructura packete */
	
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); /* creación del socket */
	if(sockfd == -1){	
		fprintf(stderr, "Error: No se abrió el socket. %d: %s \n",errno, strerror(errno));
		return -1;
	}else{
		printf("Sliffer: Socket creado\n");
	}
	
	/* Configurando modo promiscuo */
	struct ifreq ethreq;
	strncpy(ethreq.ifr_name,adapter,IFNAMSIZ);
	ioctl(sockfd,SIOCGIFFLAGS,&ethreq);
	ethreq.ifr_flags |= IFF_PROMISC;
	if(ioctl(sockfd,SIOCSIFFLAGS,&ethreq)<0){
		printf("\nNo se pudo configurar el modo promiscuo :(\n");
	}else{
		printf("\nSe configuró el modo promiscuo\n");
	}
	
	/* Ciclo de obtención de paquetes */
	while(cont>0){
		
		memset(&paquete,0, sizeof(paquete));
		memset(&saddr,0, sizeof(saddr));
		
		paquete.len=recvfrom(sockfd, paquete.buffer, MAX_BUFFER, 0,&saddr, &size_addr);
		
		if(paquete.len == 0)
			printf("\nNo se recibió mensaje \n");
		
		if(paquete.len < 0){
			fprintf(stderr, "Error: Mensaje no leído. %d: %s \n",errno, strerror(errno));
		}else{
			paquete.num_pk=atoi(packets)-cont+1;
			
			/* Creación de hilo */
	
			if(pthread_create(&hilo_anz,NULL,analiza,(void *)&paquete)){
				printf("Problema en la creación del hilo\n");
				exit(EXIT_FAILURE);
			}
			
			if(pthread_join(hilo_anz,NULL)){
				printf("Problema al enlazar con hilo_anz\n");
				exit(EXIT_FAILURE);
			}else{
				printf("Packete %i analizado!!!\n",cont);
			}
			
		}
		cont-=1;	
	}
	system("/sbin/ifconfig enp0s3 -promisc");
	
	//para obtener la carga util ocupamos la máscara de red y realizamos operaciones a nivel bit dejando los bits no utilizados en 1 al aplicar la mascara y el número de bits en 1 será la carga de relleno.
	
}

void *analiza(void *argumento){
	
	char protocolo[50]="";
	char direccionamiento[15]="";
	unsigned char tipo[2],tp_dir;
	__be16 tico;
	
	memset(&protocolo,0, sizeof(protocolo));
	memset(&direccionamiento,0, sizeof(direccionamiento));
	memset(&tipo,0, sizeof(tipo));
	
	FILE *fichero;
	
	Pack *pkt=(Pack *)argumento;
	
	struct ethhdr *chefsito;
	chefsito=(struct ethhdr*)pkt->buffer;
	
	tipo[0]=chefsito->h_proto>>8;
	tipo[1]=chefsito->h_proto;
	tico=tipo[1]<<8;
	tico=tico^tipo[0];
	
	/*Determinando tipo de direccionamiento*/
	tp_dir=chefsito->h_source[0];
	
	if(tp_dir==0XFF){
		strcpy(direccionamiento,"Difusion");
	}else if((tp_dir<<7)==0){
		strcpy(direccionamiento,"Multidifusion");
	}else{
		strcpy(direccionamiento,"Unidifusion");
	}
	
	/* Apertura de fichero */
	fichero=fopen("Reporte_Packetes.txt","a+");
	
	if(fichero==NULL){
		fichero=fopen("Reporte_Packetes.txt","w");
		fclose(fichero);
		fichero=fopen("Reporte_Packetes.txt","a+");
	}
	
	if(tico>=0X0000 && tico<=0X05DC){
		
		fprintf(fichero,"\nPaquete número: %i\nTrama tipo: IEEE 802.3 (%x)\nDescripcion: La trama no es analizable\n$$$$$$$$$$$$$$$$\n",pkt->num_pk,tico);
		
	}else if(tico>=0X0600){
		switch(tico){
			case 0X0800://IPV4
				strcpy(protocolo,"IPv4");
			break;
			case 0X86DD://IPV6
				strcpy(protocolo,"IPv6");
			break;
			case 0X0806://ARPA
				strcpy(protocolo,"ARPA");
			break;
			case 0X8808://Control de flujo de Ethernet
				strcpy(protocolo,"Control de flujo de Ethernet");
			break;
			case 0X88E5://Seguridad MAC
				strcpy(protocolo,"Seguridad MAC");
			break;
		}
		
		fprintf(fichero,"\nPaquete número: %i\nTrama tipo: Ethernet II->%s\nDestino (MAC): %x:%x:%x:%x:%x:%x\nOrigen: %x:%x:%x:%x:%x:%x\nLongitud de Trama: %i bytes\nDireccionamiento: %s\n$$$$$$$$$$$$$$$$\n",pkt->num_pk,protocolo,chefsito->h_dest[0],chefsito->h_dest[1],chefsito->h_dest[2],chefsito->h_dest[3],chefsito->h_dest[4],chefsito->h_dest[5],chefsito->h_source[0],chefsito->h_source[1],chefsito->h_source[2],chefsito->h_source[3],chefsito->h_source[4],chefsito->h_source[5],pkt->len,direccionamiento);

	}
	
	fclose(fichero);
	pthread_exit("Paquete analizado. \n");
}
