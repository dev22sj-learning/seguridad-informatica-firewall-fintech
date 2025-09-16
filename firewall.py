#!/usr/bin/env python3
"""
Firewall para FinTech Secure
Implementa filtrado de tráfico y bloqueo de sitios no autorizados
"""

import socket
import struct
import os
import sys
import datetime
import logging
from typing import List, Set

# Configuración de logging
logging.basicConfig(
    filename='firewall.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class Firewall:
    def __init__(self):
        self.blocked_sites = self.load_blocked_sites()
        self.allowed_ips = self.load_allowed_ips()
        self.logger = logging.getLogger('Firewall')
        
    def load_blocked_sites(self) -> Set[str]:
        """Carga la lista de sitios bloqueados desde archivo"""
        sites = set()
        try:
            with open('blocked_sites.txt', 'r') as f:
                for line in f:
                    site = line.strip()
                    if site and not site.startswith('#'):
                        sites.add(site)
            self.logger.info(f"Cargados {len(sites)} sitios bloqueados")
        except FileNotFoundError:
            self.logger.warning("Archivo blocked_sites.txt no encontrado. Creando uno por defecto.")
            # Crear archivo por defecto con sitios bloqueados
            default_sites = [
                "facebook.com", "instagram.com", "tiktok.com",
                "youtube.com", "netflix.com", "twitch.tv",
                "reddit.com", "thepiratebay.org", "1337x.to",
                "gmail.com", "outlook.com", "yahoo.com"
            ]
            with open('blocked_sites.txt', 'w') as f:
                for site in default_sites:
                    f.write(site + '\n')
                    sites.add(site)
        return sites
    
    def load_allowed_ips(self) -> List[str]:
        """Carga la lista de IPs permitidas desde archivo"""
        ips = []
        try:
            with open('allowed_ips.txt', 'r') as f:
                for line in f:
                    ip = line.strip()
                    if ip and not ip.startswith('#'):
                        ips.append(ip)
            self.logger.info(f"Cargadas {len(ips)} redes permitidas")
        except FileNotFoundError:
            self.logger.warning("Archivo allowed_ips.txt no encontrado. Creando uno por defecto.")
            # Crear archivo por defecto con redes permitidas
            default_ips = ["192.168.1.0/24", "10.0.0.0/8"]
            with open('allowed_ips.txt', 'w') as f:
                for ip in default_ips:
                    f.write(ip + '\n')
                    ips.append(ip)
        return ips
    
    def is_ip_in_network(self, ip: str, network: str) -> bool:
        """Verifica si una IP pertenece a una red específica"""
        try:
            ip_addr = struct.unpack('!I', socket.inet_aton(ip))[0]
            net_addr, net_bits = network.split('/')
            net_mask = (0xFFFFFFFF << (32 - int(net_bits))) & 0xFFFFFFFF
            net_addr = struct.unpack('!I', socket.inet_aton(net_addr))[0]
            return (ip_addr & net_mask) == (net_addr & net_mask)
        except:
            return False
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Verifica si una IP está permitida"""
        for network in self.allowed_ips:
            if self.is_ip_in_network(ip, network):
                return True
        return False
    
    def is_site_blocked(self, hostname: str) -> bool:
        """Verifica si un sitio está bloqueado"""
        for blocked_site in self.blocked_sites:
            if hostname.endswith(blocked_site) or blocked_site in hostname:
                return True
        return False
    
    def monitor_traffic(self):
        """Monitorea el tráfico de red (ejemplo simplificado)"""
        self.logger.info("Iniciando monitoreo de tráfico")
        
        # En una implementación real, aquí se usarían técnicas más avanzadas
        # como sockets raw o librerías especializadas (Scapy, etc.)
        
        print("Firewall activo. Monitoreando tráfico...")
        print("Presiona Ctrl+C para detener")
        
        try:
            while True:
                # Simulación de monitoreo
                # En producción, esto se reemplazaría con captura real de paquetes
                pass
                
        except KeyboardInterrupt:
            self.logger.info("Firewall detenido por el usuario")
            print("\nFirewall detenido")

def main():
    """Función principal"""
    print("=== Firewall FinTech Secure ===")
    print("Inicializando firewall...")
    
    # Verificar permisos de administrador
    if os.name != 'nt' and os.geteuid() != 0:
        print("Error: Este script requiere privilegios de administrador")
        sys.exit(1)
    
    firewall = Firewall()
    
    # Ejemplo de verificación
    test_ips = ["192.168.1.100", "8.8.8.8", "10.0.0.5"]
    test_sites = ["facebook.com", "google.com", "youtube.com"]
    
    print("\n=== Pruebas de verificación ===")
    
    print("\nVerificación de IPs:")
    for ip in test_ips:
        status = "PERMITIDA" if firewall.is_ip_allowed(ip) else "BLOQUEADA"
        print(f"IP {ip}: {status}")
    
    print("\nVerificación de sitios:")
    for site in test_sites:
        status = "BLOQUEADO" if firewall.is_site_blocked(site) else "PERMITIDO"
        print(f"Sitio {site}: {status}")
    
    # Iniciar monitoreo (en implementación real)
    # firewall.monitor_traffic()

if __name__ == "__main__":
    main()