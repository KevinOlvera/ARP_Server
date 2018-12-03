#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <sys/time.h>
#include <mysql/mysql.h>

unsigned char MACOrigen[6];
unsigned char IPOrigen[4];

unsigned char MACDestino[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
unsigned char IPDestino[4] = {0x00,0x00,0x00,0x00};

unsigned char tramaEnv[1514], tramaRec[1514];
unsigned char MACbro[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char ethertype[2] = {0x08,0x06};
unsigned char HW[2] = {0x00,0x01};
unsigned char PR[2] = {0x08,0x00};
unsigned char LDH[1] = {0x06};
unsigned char LDP[1] = {0x04};
unsigned char epcode_s[2] = {0x00, 0x01};
unsigned char epcode_r[2] = {0x00, 0x02};

struct timeval start, end;
long mtime, seconds, useconds;

MYSQL *connection;
MYSQL_RES *result;
MYSQL_ROW row;
char consult[100] = "";


int obtenerDatos(int ds);
void estructuraTrama(unsigned char *trama, int index);
void obtenerIPDestino(int index);
void enviaTrama(int ds, int indice, unsigned char *trama);
void recibeTrama(int ds, unsigned char *trama);
void imprimeTrama(unsigned char *trama, int tam);

void BD_MySQL_Connect();
void BD_MySQL_Close();
void BD_MySQL_Save_Data(unsigned char *trama);
void BD_MySQL_Show_Data();
void BD_MySQL_Reset_Data();