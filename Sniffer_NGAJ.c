//Librerias Comunes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//Librerias socket
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
//Librerias extra
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>

#define TAM_BUFF 	2000

typedef struct Pack{
	int pk_num;
	int pk_len;
	int pk_lenu;
	unsigned char pk_buff[TAM_BUFF];
}Trama;

int pk_anz=0;
int pk_nanz=0;
int pk_ipv4=0;
int pk_ipv6=0;
int pk_a	rpa=0;
int pk_cfe=0;
int pk_segmac=0;


void *packet_Analize(void *arg){
	
	unsigned char tram_tip[2];
	unsigned char fst_bt;
	__be16 pro_tip;
	char proto[50];
	char tip_direc[15];
	
	Trama *tram=(Trama *)arg;
	
	struct ethhdr *ether;
	ether=(struct ethhdr*)tram->pk_buff;
	
	FILE *arch;
	
	memset(&proto,0, sizeof(proto));
	memset(&tip_direc,0, sizeof(tip_direc));
	memset(&tram_tip,0, sizeof(tram_tip));
	
	fst_bt=ether->h_source[0];
	
	if(fst_bt==0XFF){
		strcpy(tip_direc,"Difusion");
	}else if((fst_bt<<7)==255){
		strcpy(tip_direc,"Multidifusion");
	}else{
		strcpy(tip_direc,"Unidifusion");
	}
	
	tram_tip[0]=ether->h_proto>>8;
	tram_tip[1]=ether->h_proto;
	pro_tip=tram_tip[1]<<8;
	pro_tip=pro_tip^tram_tip[0];
	
	arch=fopen("Tramas.txt","a+");
	
	if(arch==NULL){
		arch=fopen("Tramas.txt","w");
		fclose(arch);
		arch=fopen("Tramas.txt","a+");
	}
	
	if(pro_tip>=0X0000 && pro_tip<=0X05DC){
		
		fprintf(arch,"\n***Trama %i***\nTipo Trama: IEEE 802.3  -> %x\n**La trama no se puede analizar**\n\n",tram->pk_num,pro_tip);
		pk_nanz++;
		
	}else if(pro_tip>=0X0600){
		switch(pro_tip){
			case 0X0800:
				strcpy(proto,"IPv4");
				pk_ipv4++;
			break;
			case 0X86DD:
				strcpy(proto,"IPv6");
				pk_ipv6++;
			break;
			case 0X0806:
				strcpy(proto,"ARPA");
				pk_arpa++;
			break;
			case 0X8808:
				strcpy(proto,"Control de Flujo de Ethernet");
				pk_cfe++;
			break;
			case 0X88E5:
				strcpy(proto,"Seguridad MAC");
				pk_segmac++;
			break;
		}
		
		tram->pk_lenu=tram->pk_len-14;
		pk_anz++;
		
		fprintf(arch,"\n***Trama %i***\nTipo Trama: Ethernet II\nProtocolo: %s\nDireccionamiento: %s\nMAC Origen: %x:%x:%x:%x:%x:%x\nMAC Destino: %x:%x:%x:%x:%x:%x\nLongitud Trama: %i bytes\nLongitud Trama Util: %i bytes\n\n",tram->pk_num,proto,tip_direc,ether->h_source[0],ether->h_source[1],ether->h_source[2],ether->h_source[3],ether->h_source[4],ether->h_source[5],ether->h_dest[0],ether->h_dest[1],ether->h_dest[2],ether->h_dest[3],ether->h_dest[4],ether->h_dest[5],tram->pk_len,tram->pk_lenu);

	}
	
	fclose(arch);
	pthread_exit("Hilo Terminado\n");
}

void general_Report(int pk_total){

	FILE *arch;
	arch=fopen("Reporte_Tramas.txt","a+");
	
	if(arch==NULL){
		arch=fopen("Reporte_Tramas.txt","w");
		fclose(arch);
		arch=fopen("Reporte_Tramas.txt","a+");
	}
	
	fprintf(arch,"\n\t~~Analisis completado~~\nTramas capturadas: %i\nTramas IEEE 802.3: %i\nTramas Ethernet II: %i\n\tCon Protocolo IPv4: %i\n\tCon Protocolo IPv6: %i\n\tCon Protocolo ARPA: %i\n\tCon Protocolo Control-Flujo-Ethernet: %i\n\tCon Protocolo Seguridad MAC: %i\n\n",pk_total,pk_nanz,pk_anz,pk_ipv4,pk_ipv6,pk_arpa,pk_cfe,pk_segmac);

}

int main(){
	
	char adaptador[10]="";
	char num_paq[10]="";
	int cont;
	int len_addr;
	int sockfd;  
	
	printf("\nEscriba su adaptador de red: ");
	gets(adaptador);
	printf("\nEscriba el número de paquetes a analizar: ");
	gets(num_paq);
	
	cont=atoi(num_paq);
	
	Trama packet;
	pthread_t hilo_anz;
	struct sockaddr saddr;
	
	len_addr=sizeof(saddr);
	
	
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sockfd == -1){	
		fprintf(stderr, "[Error]: No es posible abrir el socket. %d: %s \n",errno, strerror(errno));
		return -1;
	}else{
		printf("[Sistema]: Socket abierto con éxito\n");
	}
	
	struct ifreq ethreq;
	strncpy(ethreq.ifr_name,adaptador,IFNAMSIZ);
	ioctl(sockfd,SIOCGIFFLAGS,&ethreq);
	ethreq.ifr_flags |= IFF_PROMISC;
	if(ioctl(sockfd,SIOCSIFFLAGS,&ethreq)<0){
		printf("\n[Error]: Adaptador no configurado\n");
		return -1;
	}else{
		printf("\n[Sistema]: Adaptador configurado en modo promiscuo\n");
	}
	
	while(cont>0){
		
		memset(&packet,0, sizeof(packet));
		memset(&saddr,0, sizeof(saddr));
		
		packet.pk_len=recvfrom(sockfd, packet.pk_buff, TAM_BUFF, 0,&saddr, &len_addr);
		
		if(packet.pk_len == 0)
			printf("\n[Error]: No se recibió mensaje \n");
		
		if(packet.pk_len < 0){
			fprintf(stderr, "[Error]: Mensaje no leído. %d: %s \n",errno, strerror(errno));
		}else{
			packet.pk_num=atoi(num_paq)-cont+1;
	
			if(pthread_create(&hilo_anz,NULL,packet_Analize,(void *)&packet)){
				printf("[Error]: No pudo crearse el hilo\n");
				exit(EXIT_FAILURE);
			}
			
			if(pthread_join(hilo_anz,NULL)){
				printf("[Error]: No pse pudo conectar al hilo\n");
				exit(EXIT_FAILURE);
			}else{
				printf("Paquete %i analizado!!!\n",packet.pk_num);
			}
			
		}
		cont--;
			
	}
	
	general_Report(atoi(num_paq));
	
	system("/sbin/ifconfig enp0s3 -promisc");
	
}


