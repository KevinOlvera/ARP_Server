#include "ARP.c"

int main(int argc, char const *argv[])
{
	int packet_socket, indice;

	BD_MySQL_Connect();
	BD_MySQL_Reset_Data();
    
	packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

	if(packet_socket == -1)
	{
		perror("Error al abrir el socket");
		exit(1);
	}
	else
	{
		perror("Exito al abrir el socket");
		indice = obtenerDatos(packet_socket);
        
		int index;

		for(index = 1;index < 255;index++)
		{
			estructuraTrama(tramaEnv, index);
			enviaTrama(packet_socket, indice, tramaEnv);
			//imprimeTrama(tramaEnv, 42);
			recibeTrama(packet_socket, tramaRec);
		}
	}

	BD_MySQL_Show_Data();
	BD_MySQL_Close();
	
	close(packet_socket);
	return 1;
}