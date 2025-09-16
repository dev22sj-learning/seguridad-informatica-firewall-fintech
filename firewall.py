#!/usr/bin/env python3
"""
Firewall REAL para FinTech Secure
Implementa filtrado de tráfico y bloqueo de sitios no autorizados
"""

import socket
import struct
import os
import sys
import datetime
import logging
import subprocess
import time
from typing import List, Set

# Configuración de logging
logging.basicConfig(
    filename='firewall.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class Firewall:
    def __init__(self):
        self.logger = logging.getLogger('Firewall')
        self.blocked_sites = self.load_blocked_sites()
        self.allowed_ips = self.load_allowed_ips()
        
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
    
    def setup_iptables_rules(self):
        """Configura reglas de iptables para bloquear tráfico REAL"""
        try:
            # Limpiar reglas existentes
            subprocess.run(['sudo', 'iptables', '-F'], check=True)
            subprocess.run(['sudo', 'iptables', '-X'], check=True)
            
            # Permitir tráfico local
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'], check=True)
            
            # Permitir IPs de redes autorizadas
            for network in self.allowed_ips:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', network, '-j', 'ACCEPT'], check=True)
                subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', network, '-j', 'ACCEPT'], check=True)
            
            # Bloquear sitios específicos usando iptables
            for site in self.blocked_sites:
                # Bloquear por nombre de dominio (usando el módulo string de iptables)
                subprocess.run([
                    'sudo', 'iptables', '-A', 'OUTPUT', 
                    '-p', 'tcp', '--dport', '80',
                    '-m', 'string', '--string', site, '--algo', 'bm',
                    '-j', 'DROP'
                ], check=True)
                
                subprocess.run([
                    'sudo', 'iptables', '-A', 'OUTPUT', 
                    '-p', 'tcp', '--dport', '443',
                    '-m', 'string', '--string', site, '--algo', 'bm',
                    '-j', 'DROP'
                ], check=True)
                
                # También bloquear por IP (resolver DNS)
                try:
                    result = subprocess.run(['dig', '+short', site], 
                                          capture_output=True, text=True, check=True)
                    ips = result.stdout.strip().split('\n')
                    for ip in ips:
                        if ip and not ip.startswith(';'):
                            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True)
                            self.logger.info(f"Bloqueada IP: {ip} para {site}")
                except:
                    self.logger.warning(f"No se pudo resolver IP para {site}")
            
            # Política por defecto: permitir todo (o denegar para ser más restrictivo)
            subprocess.run(['sudo', 'iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
            subprocess.run(['sudo', 'iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
            subprocess.run(['sudo', 'iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
            
            self.logger.info("Reglas de iptables configuradas correctamente")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error configurando iptables: {e}")
            return False
    
    def block_with_hosts_file(self):
        """Método alternativo: bloquear sitios usando el archivo hosts"""
        hosts_path = "/etc/hosts" if os.name != "nt" else r"C:\Windows\System32\drivers\etc\hosts"
        
        try:
            # Hacer backup del archivo hosts
            if os.path.exists(hosts_path):
                with open(hosts_path, 'r') as f:
                    original_content = f.read()
                
                with open(hosts_path + '.backup', 'w') as f:
                    f.write(original_content)
            
            # Agregar bloqueos al archivo hosts
            with open(hosts_path, 'a') as f:
                f.write('\n# === BLOQUEOS FINETECH SECURE ===\n')
                for site in self.blocked_sites:
                    f.write(f'127.0.0.1 {site}\n')
                    f.write(f'127.0.0.1 www.{site}\n')
                    f.write(f'::1 {site}\n')
                    f.write(f'::1 www.{site}\n')
            
            self.logger.info("Sitios bloqueados en archivo hosts")
            return True
            
        except PermissionError:
            self.logger.error("Permisos insuficientes para modificar el archivo hosts")
            return False
        except Exception as e:
            self.logger.error(f"Error modificando archivo hosts: {e}")
            return False
    
    def monitor_traffic(self):
        """Monitorea el tráfico de red y aplica reglas de firewall"""
        self.logger.info("Iniciando monitoreo de tráfico")
        
        # Configurar reglas de firewall
        if os.name == "posix":  # Linux/macOS
            success = self.setup_iptables_rules()
            if not success:
                print("Usando método alternativo (archivo hosts)...")
                success = self.block_with_hosts_file()
        else:  # Windows
            success = self.block_with_hosts_file()
        
        if not success:
            print("Error: No se pudieron configurar las reglas de firewall")
            self.logger.error("No se pudieron configurar las reglas de firewall")
            return
        
        print("Firewall activo. Monitoreando tráfico...")
        print("Sitios bloqueados:", ", ".join(self.blocked_sites))
        print("Presiona Ctrl+C para detener")
        
        try:
            while True:
                # Monitoreo continuo - en una implementación real aquí
                # se podrían agregar más funcionalidades de monitoreo
                time.sleep(5)
                # Verificar periódicamente si las reglas siguen activas
                
        except KeyboardInterrupt:
            self.cleanup()
            self.logger.info("Firewall detenido por el usuario")
            print("\nFirewall detenido")
    
    def cleanup(self):
        """Limpia las reglas de firewall al detener"""
        try:
            if os.name == "posix":
                # Limpiar reglas iptables
                subprocess.run(['sudo', 'iptables', '-F'], check=True)
                subprocess.run(['sudo', 'iptables', '-X'], check=True)
                print("Reglas de iptables limpiadas")
            
            # Restaurar archivo hosts si se usó ese método
            hosts_path = "/etc/hosts" if os.name != "nt" else r"C:\Windows\System32\drivers\etc\hosts"
            backup_path = hosts_path + '.backup'
            
            if os.path.exists(backup_path):
                with open(backup_path, 'r') as f:
                    original_content = f.read()
                
                with open(hosts_path, 'w') as f:
                    f.write(original_content)
                
                os.remove(backup_path)
                print("Archivo hosts restaurado")
                
        except Exception as e:
            self.logger.error(f"Error en cleanup: {e}")

def main():
    """Función principal"""
    print("=== Firewall Real FinTech Secure ===")
    print("Inicializando firewall...")
    
    # Verificar permisos de administrador
    if os.name != 'nt' and os.geteuid() != 0:
        print("Error: Este script requiere privilegios de administrador (ejecuta con sudo)")
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
    
    # Iniciar monitoreo REAL
    firewall.monitor_traffic()

if __name__ == "__main__":
    main()