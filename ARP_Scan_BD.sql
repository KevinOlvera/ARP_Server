CREATE DATABASE ARP_Scan;

USE ARP_Scan;

CREATE TABLE PC
(
    ID int NOT NULL AUTO_INCREMENT PRIMARY KEY,
    IP_Address VARCHAR(15) NOT NULL,
    MAC_Address VARCHAR(17) NOT NULL
);