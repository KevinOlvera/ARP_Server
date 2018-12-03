#include "ARP.h"

int obtenerDatos(int ds)
{
	struct ifreq nic;
	int indice,i;
	char nombre[10], dir_ip[14], select;
	
	//printf("Insertar el nombre de la interfaz:  ");
	//scanf("%s", nombre);
	printf("Que interfaz deseas usar:\n 1.-enp2s0\n 2.-wlp3s0\n -> ");
	scanf("%c", &select);
	switch(select)
	{
		case '1':
			printf("Usando la interfaz enp2s0\n\n");
			strcpy(nombre, "enp2s0");
		break;
		case '2':
			printf("Usando la interfaz wlp3s0\n\n");
			strcpy(nombre, "wlp3s0");
		break;
		default:
			printf("No se selecciono una interfaz de red adecuada.\n");
			exit(1);
	}

	strcpy(nic.ifr_name, nombre);
	
	if(ioctl(ds, SIOCGIFINDEX, &nic) == -1)
	{
		perror("Error al obtener el indice\n");
		exit(1);
	}
	else
	{
		indice = nic.ifr_ifindex;
	}
	
	if(ioctl(ds, SIOCGIFHWADDR, &nic ) == -1)
	{
		perror("Error al obtener la MAC\n");
		exit(1);
	}
    else
    {
		memcpy(MACOrigen, nic.ifr_hwaddr.sa_data+0, 6);
		printf("Mi direccion MAC es: ");
		
		for( i = 0 ; i < 6 ; i++ )
		{
			if(i == 5)
				printf("%.2X", MACOrigen[i]);
			else
				printf("%.2X:", MACOrigen[i]);
		}
	}

	if(ioctl(ds, SIOCGIFADDR, &nic) == -1)
	{
		perror("Error al obtener la dirección IP\n");
		exit(1);
	}
	else
	{
		memcpy(IPOrigen, nic.ifr_addr.sa_data+2, 4);
		printf("\nMi direccion IP es: ");
		
		for( i = 0 ; i < 4 ; i++ ){
			if( i == 3 )
				printf("%d", IPOrigen[i]);
			else 
				printf("%d.", IPOrigen[i]);
		}
	}

	printf("\n");

	return indice;
}

void estructuraTrama(unsigned char *trama, int index)
{
	memcpy(trama+0, MACbro, 6);
	memcpy(trama+6, MACOrigen, 6);
	memcpy(trama+12, ethertype, 2);
	memcpy(trama+14, HW, 2);
	memcpy(trama+16, PR, 2);
	memcpy(trama+18, LDH, 1);
	memcpy(trama+19, LDP, 1);
	memcpy(trama+20, epcode_s, 2);
	memcpy(trama+22, MACOrigen, 6);
	memcpy(trama+28, IPOrigen, 4);
	memcpy(trama+32, MACDestino, 6);

	obtenerIPDestino(index);

	memcpy(trama+38, IPDestino, 4);
}

void obtenerIPDestino(int index)
{
    IPDestino[0] = IPOrigen[0];
	IPDestino[1] = IPOrigen[1];
	IPDestino[2] = IPOrigen[2];

	int i;
	char ip_destino[14] = "";
	char aux[14] = "";
	
	for( i = 0 ; i < 3 ; i++ ){
		sprintf(aux, "%d.", IPDestino[i]);
		strcat(ip_destino, aux);
	}

	sprintf(aux, "%d", index);
	strcat(ip_destino, aux);

	inet_aton(ip_destino, (struct in_addr *)IPDestino);
}

void enviaTrama(int ds, int indice, unsigned char *trama)
{
	int tam;   
	struct sockaddr_ll interfaz;
	memset(&interfaz, 0x00, sizeof(interfaz));
	interfaz.sll_family = AF_PACKET;
	interfaz.sll_protocol = htons(ETH_P_ALL);
	interfaz.sll_ifindex = indice;
	tam=sendto(ds, trama, 42, 0, (struct sockaddr *)&interfaz, sizeof(interfaz));
	
	if(tam == -1)
	{
		perror("Error al enviar");
		exit(1);   
	}
	else
	{
		//perror("Exito al enviar");  
	}
}

void imprimeTrama(unsigned char *trama, int tam)
{
	int i;

	for( i = 0 ; i < tam ; i++ )
	{
		if( i%16 == 0 )
			printf("\n");
		printf("%.2X ", trama[i]);
	}

	printf("\n");
}

void recibeTrama(int ds, unsigned char *trama)
{
	int tam, flag = 0;

	gettimeofday(&start, NULL);
	mtime = 0;
    
    while(mtime < 1000)
	{
		tam = recvfrom(ds, trama, 1514, MSG_DONTWAIT, NULL, 0);

		if( tam == -1 )
		{
			//perror("Error al recibir");
		}
		else
		{
			if( !memcmp(trama+0, MACOrigen, 6) && !memcmp(trama+12, ethertype, 2) && !memcmp(trama+20, epcode_r, 2) && !memcmp(trama+28, IPDestino, 4) )
			{
				//imprimeTrama(trama, tam);
				BD_MySQL_Save_Data(trama);
				flag = 1;
			}
		}
	
		gettimeofday(&end, NULL);

		seconds  = end.tv_sec  - start.tv_sec;
		useconds = end.tv_usec - start.tv_usec;

		mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
		
		if( flag == 1 )
		{
			//printf("Elapsed time: %ld milliseconds\n", mtime);
			break;
		}
	}

	if( flag == 0 ){
		//perror("Error al recibir");
		//printf("Elapsed time: %ld milliseconds\n", mtime);
	}
}

void BD_MySQL_Connect()
{
	char *server = "localhost";
	char *user = "root";
	char *password = "root";
	char *database = "ARP_Scan";

	connection = mysql_init(NULL);
	/* Connect to database */
	
	if (!mysql_real_connect(connection, server, user, password, database, 0, NULL, 0))
	{
		fprintf(stderr, "%s\n", mysql_error(connection));
		exit(1);
	}
	else
	{
		perror("Exito al conectar con la base de datos");
	}
}

void BD_MySQL_Close()
{
	mysql_free_result(result);
	mysql_close(connection);
}

void BD_MySQL_Save_Data(unsigned char *trama)
{
	char ip[15] = "";
	char aux_ip[15] = "";
	char mac[17] = "";
	char aux_mac[17] = "";

	int i;

	for(i = 6;i < 12;i++)
	{
		if(i != 11)
			sprintf(aux_mac, "%.2X:", trama[i]);		
		else
			sprintf(aux_mac, "%.2X", trama[i]);

		strcat(mac, aux_mac);
	}

	for(i = 28;i < 32;i++)
	{
		if(i != 31)
			sprintf(aux_ip, "%d.", trama[i]);
		else
			sprintf(aux_ip, "%d", trama[i]);

		strcat(ip, aux_ip);
	}

	sprintf(consult, "insert into PC values('%s', '%s');", ip, mac);
	
	if (mysql_query(connection, consult))
	{
		fprintf(stderr, "%s\n", mysql_error(connection));
		exit(1);
	}
	else
		printf("\nSe agrego a %s - %s", mac, ip);

}

void BD_MySQL_Show_Data()
{
	sprintf(consult, "select * from PC;");

	if((mysql_query(connection, consult) == 0))
	{
		result = mysql_use_result(connection);

		printf("\n\n\n+---------------+-------------------+\n");
		printf("|  IP_Address\t|    MAC_Address    |\n");
		printf("+---------------+-------------------+\n");

		while(row = mysql_fetch_row(result))
			printf("| %s\t| %s |\n", row[0], row[1]);
		
		printf("+---------------+-------------------+\n");
	}

	if(!mysql_eof(result))
		printf("Error de lectura %s\n", mysql_error(connection));
}

void BD_MySQL_Reset_Data()
{
	sprintf(consult, "truncate PC;");
	mysql_query(connection, consult);
	if((mysql_query(connection, consult) == 0))
	{
		result = mysql_use_result(connection);
	}
}