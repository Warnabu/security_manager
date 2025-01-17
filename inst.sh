#!/bin/bash

# Comprobar si se ejecuta como root
if [ "$(id -u)" -ne 0 ]; then
    echo "Este script debe ejecutarse como root o con sudo." 
    exit 1
fi

# Instalar las dependencias necesarias
echo "Instalando dependencias necesarias..."
apt-get update
apt-get install -y nmap iftop iptables fail2ban

# Verificar si las herramientas necesarias están instaladas
command -v nmap >/dev/null 2>&1 || { echo "Error: nmap no se pudo instalar." >&2; exit 1; }
command -v iftop >/dev/null 2>&1 || { echo "Error: iftop no se pudo instalar." >&2; exit 1; }
command -v iptables >/dev/null 2>&1 || { echo "Error: iptables no se pudo instalar." >&2; exit 1; }
command -v fail2ban-client >/dev/null 2>&1 || { echo "Error: fail2ban no se pudo instalar." >&2; exit 1; }

echo "Dependencias instaladas correctamente."

# Copiar el script principal al directorio adecuado y hacerlo ejecutable
echo "Instalando el script 'security_manager'..."

cp security_manager.sh /usr/local/bin/security_manager
chmod +x /usr/local/bin/security_manager

# Confirmar instalación
echo "El script ha sido instalado correctamente como 'security_manager'. Puedes ejecutarlo con el comando 'security_manager'."

# Fin
echo "Instalación completada. Puedes usar el script ejecutando 'security_manager' desde cualquier ubicación."
