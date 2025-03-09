#!/usr/bin/env python3

import os
import subprocess
import shutil
import sys

# Verificar si el script se ejecuta como root
if os.geteuid() != 0:
    print("Este script debe ejecutarse como root o con sudo.")
    sys.exit(1)

# Lista de los paquetes necesarios
packages = ["nmap", "iftop", "iptables", "fail2ban", "net-tools", "lynis", "netdiscover", "iptables-persistent"]

print("Instalando dependencias necesarias...")
subprocess.run(["apt-get", "update"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
subprocess.run(["apt-get", "install", "-y"] + packages, check=True)

# Verificar si las herramientas se instalaron correctamente
for pkg in ["nmap", "iftop", "iptables", "fail2ban-client"]:
    if shutil.which(pkg) is None:
        print(f"Error: {pkg} no se pudo instalar.", file=sys.stderr)
        sys.exit(1)

print("Dependencias instaladas correctamente.")

# Copiar el script principal y hacerlo ejecutable
script_src = "security_manager.py"
script_dst = "/usr/local/bin/security_manager"

if os.path.exists(script_src):
    shutil.copy(script_src, script_dst)
    os.chmod(script_dst, 0o755)  # Dar permisos de ejecución
    print(f"El script ha sido instalado correctamente como 'security_manager'. Puedes ejecutarlo con el comando 'security_manager'.")
else:
    print(f"Advertencia: No se encontró '{script_src}', no se ha copiado.")

print("Instalación completada.")
