#!/usr/bin/env python3
"""
Firewall REAL Mejorado para FinTech Secure
Bloquea efectivamente Instagram, YouTube y todos los sitios de la lista
"""

import socket
import struct
import os
import sys
import datetime
import logging
import subprocess
import time
import re
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
        self.resolved_ips = set()
        
    def load_blocked_sites(self) -> Set[str]:
        """Carga la lista de sitios bloqueados desde archivo"""
        sites = set()
        try:
            with open('blocked_sites.txt', 'r') as f:
                for line in f:
                    site = line.strip().lower()
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
                "gmail.com", "outlook.com", "yahoo.com",
                # Dominios adicionales de Instagram y YouTube
                "instagram.com", "www.instagram.com", "api.instagram.com",
                "youtube.com", "www.youtube.com", "m.youtube.com",
                "youtu.be", "ggpht.com", "ytimg.com",
                "googleapis.com"  # YouTube usa este dominio
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
            default_ips = ["192.168.1.0/24", "10.0.0.0/8", "127.0.0.0/8"]
            with open('allowed_ips.txt', 'w') as f:
                for ip in default_ips:
                    f.write(ip + '\n')
                    ips.append(ip)
        return ips
    
    def resolve_domains(self):
        """Resuelve todos los dominios bloqueados a IPs"""
        self.logger.info("Resolviendo IPs de dominios bloqueados...")
        
        for site in self.blocked_sites:
            try:
                # Resolver IPv4
                result = subprocess.run(['dig', '+short', 'A', site], 
                                      capture_output=True, text=True, timeout=10)
                ips = result.stdout.strip().split('\n')
                for ip in ips:
                    if ip and not ip.startswith(';') and self.is_valid_ip(ip):
                        self.resolved_ips.add(ip)
                        self.logger.info(f"Resuelto {site} -> {ip}")
                
                # Resolver IPv6
                result6 = subprocess.run(['dig', '+short', 'AAAA', site], 
                                       capture_output=True, text=True, timeout=10)
                ips6 = result6.stdout.strip().split('\n')
                for ip in ips6:
                    if ip and not ip.startswith(';') and self.is_valid_ip(ip):
                        self.resolved_ips.add(ip)
                        
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                self.logger.warning(f"No se pudo resolver {site}")
    
    def is_valid_ip(self, ip: str) -> bool:
        """Verifica si una cadena es una IP válida"""
        try:
            socket.inet_pton(socket.AF_INET, ip)
            return True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
                return True
            except socket.error:
                return False
    
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
        hostname = hostname.lower()
        for blocked_site in self.blocked_sites:
            if (hostname == blocked_site or 
                hostname.endswith('.' + blocked_site) or 
                blocked_site in hostname):
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
            
            # Resolver todos los dominios a IPs
            self.resolve_domains()
            
            # Bloquear por IPs resueltas
            for ip in self.resolved_ips:
                subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True)
                self.logger.info(f"Regla iptables: BLOQUEADO {ip}")
            
            # Bloquear por nombres de dominio (para nuevos dominios no resueltos)
            for site in self.blocked_sites:
                # HTTP
                subprocess.run([
                    'sudo', 'iptables', '-A', 'OUTPUT', 
                    '-p', 'tcp', '--dport', '80',
                    '-m', 'string', '--string', site, '--algo', 'bm',
                    '-j', 'DROP'
                ], check=True)
                
                # HTTPS
                subprocess.run([
                    'sudo', 'iptables', '-A', 'OUTPUT', 
                    '-p', 'tcp', '--dport', '443',
                    '-m', 'string', '--string', site, '--algo', 'bm',
                    '-j', 'DROP'
                ], check=True)
                
                # DNS
                subprocess.run([
                    'sudo', 'iptables', '-A', 'OUTPUT', 
                    '-p', 'udp', '--dport', '53',
                    '-m', 'string', '--string', site, '--algo', 'bm',
                    '-j', 'DROP'
                ], check=True)
            
            # Política por defecto
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
                    f.write(f'0.0.0.0 {site}\n')
                    f.write(f'0.0.0.0 www.{site}\n')
                    f.write(f'::1 {site}\n')
                    f.write(f'::1 www.{site}\n')
                    
                    # Dominios adicionales específicos para Instagram y YouTube
                    if site == "instagram.com":
                        f.write('127.0.0.1 api.instagram.com\n')
                        f.write('127.0.0.1 graph.instagram.com\n')
                        f.write('0.0.0.0 api.instagram.com\n')
                        f.write('0.0.0.0 graph.instagram.com\n')
                    
                    if site == "youtube.com":
                        f.write('127.0.0.1 m.youtube.com\n')
                        f.write('127.0.0.1 youtu.be\n')
                        f.write('127.0.0.1 ggpht.com\n')
                        f.write('127.0.0.1 ytimg.com\n')
                        f.write('0.0.0.0 m.youtube.com\n')
                        f.write('0.0.0.0 youtu.be\n')
                        f.write('0.0.0.0 ggpht.com\n')
                        f.write('0.0.0.0 ytimg.com\n')
            
            # Flush DNS cache
            self.flush_dns_cache()
            
            self.logger.info("Sitios bloqueados en archivo hosts")
            return True
            
        except PermissionError:
            self.logger.error("Permisos insuficientes para modificar el archivo hosts")
            return False
        except Exception as e:
            self.logger.error(f"Error modificando archivo hosts: {e}")
            return False
    
    def flush_dns_cache(self):
        """Limpiar cache DNS"""
        try:
            if os.name == "posix":
                if sys.platform == "darwin":  # macOS
                    subprocess.run(['sudo', 'dscacheutil', '-flushcache'], check=True)
                    subprocess.run(['sudo', 'killall', '-HUP', 'mDNSResponder'], check=True)
                else:  # Linux
                    subprocess.run(['sudo', 'systemctl', 'restart', 'systemd-resolved'], check=True)
            else:  # Windows
                subprocess.run(['ipconfig', '/flushdns'], check=True)
        except:
            self.logger.warning("No se pudo flush DNS cache")
    
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
        print("Sitios bloqueados:", ", ".join(sorted(self.blocked_sites)))
        print("IPs bloqueadas:", len(self.resolved_ips))
        print("Presiona Ctrl+C para detener")
        
        try:
            while True:
                # Monitoreo continuo - verificar periódicamente
                time.sleep(30)
                # Re-resolver dominios cada 30 minutos para actualizar IPs
                if len(self.resolved_ips) > 0:
                    time.sleep(1800)  # 30 minutos
                    old_ips = self.resolved_ips.copy()
                    self.resolved_ips.clear()
                    self.resolve_domains()
                    if old_ips != self.resolved_ips:
                        self.logger.info("IPs actualizadas, reconfigurando reglas...")
                        self.setup_iptables_rules()
                
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
                self.flush_dns_cache()
                print("Archivo hosts restaurado")
                
        except Exception as e:
            self.logger.error(f"Error en cleanup: {e}")

def main():
    """Función principal"""
    print("=== Firewall Real Mejorado FinTech Secure ===")
    print("Inicializando firewall...")
    
    # Verificar permisos de administrador
    if os.name != 'nt' and os.geteuid() != 0:
        print("Error: Este script requiere privilegios de administrador (ejecuta con sudo)")
        sys.exit(1)
    
    firewall = Firewall()
    
    # Mostrar información de bloqueo
    print(f"\nSitios a bloquear: {len(firewall.blocked_sites)}")
    for i, site in enumerate(sorted(firewall.blocked_sites), 1):
        print(f"{i:2d}. {site}")
    
    # Iniciar monitoreo REAL
    firewall.monitor_traffic()

if __name__ == "__main__":
    main()