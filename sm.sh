#!/bin/bash



# Comprobar si el script se está ejecutando como root
if [ "$(id -u)" -ne 0 ]; then
    echo "Este script debe ejecutarse como root o con sudo." 
    exit 1
fi

# Función para mostrar el menú principal
mostrar_menu() {
    clear
    echo "******************************"
    echo "*  Gestión Avanzada de Seguridad *"
    echo "******************************"
    echo "1. Configurar Firewall"
    echo "2. Configuración de Fail2Ban (SSH)"
    echo "3. Limitar Conexiones por IP (Prevención DDoS)"
    echo "4. Escaneo de Puertos Abiertos"
    echo "5. Monitoreo de Tráfico en Tiempo Real"
    echo "6. Análisis de Logs (SSH y Sistema)"
    echo "7. Escaneo de la Red Local"
    echo "8. Escaneo de una Red Externa"
    echo "9. Generar Reporte de Seguridad"
    echo "10. Salir"
    echo "******************************"
    read -p "Selecciona una opción [1-10]: " opcion
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 1 Función para configurar el firewall
configurar_firewall() {
    clear
    echo "*****************************"
    echo "*  Configuración del Firewall  *"
    echo "*****************************"
    echo "1. Limpiar todas las reglas del firewall"
    echo "2. Permitir tráfico de un puerto específico"
    echo "3. Bloquear tráfico de una IP específica"
    echo "4. Permitir tráfico de una IP específica"
    echo "5. Permitir tráfico en un rango de IPs"
    echo "6. Ver reglas actuales del firewall"
    echo "7. Volver al menú principal"
    echo "*****************************"
    read -p "Selecciona una opción [1-7]: " opcion_firewall

    case $opcion_firewall in
        1)
            limpiar_reglas
            ;;
        2)
            permitir_puerto
            ;;
        3)
            bloquear_ip
            ;;
        4)
            permitir_ip
            ;;
        5)
            permitir_rango_ip
            ;;
        6)
            ver_reglas_firewall
            ;;
        7)
            return
            ;;
        *)
            echo "Opción inválida. Intenta de nuevo."
            ;;
    esac
    read -p "Presiona Enter para continuar..."
}

# Limpiar todas las reglas del firewall
limpiar_reglas() {
    echo "Limpiando todas las reglas del firewall..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    echo "Reglas del firewall limpiadas."
}

# Permitir tráfico de un puerto específico
permitir_puerto() {
    read -p "Introduce el número de puerto a permitir (Ej: 8080): " puerto
    read -p "¿Deseas permitir tráfico TCP o UDP? (tcp/udp): " tipo
    iptables -A INPUT -p $tipo --dport $puerto -j ACCEPT
    echo "Tráfico en el puerto $puerto permitido ($tipo)."
}

# Bloquear tráfico de una IP específica
bloquear_ip() {
    read -p "Introduce la IP a bloquear: " ip
    iptables -A INPUT -s $ip -j DROP
    echo "La IP $ip ha sido bloqueada."
}

# Permitir tráfico de una IP específica
permitir_ip() {
    read -p "Introduce la IP a permitir: " ip
    iptables -A INPUT -s $ip -j ACCEPT
    echo "La IP $ip ha sido permitida."
}

# Permitir tráfico de un rango de IPs
permitir_rango_ip() {
    read -p "Introduce el rango de IPs a permitir (Ej: 192.168.1.0/24): " rango
    iptables -A INPUT -s $rango -j ACCEPT
    echo "El rango de IPs $rango ha sido permitido."
}

# Ver reglas actuales del firewall
ver_reglas_firewall() {
    iptables -L
    iptables -t nat -L
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# 2 Función para mostrar el menú de configuración de Fail2Ban
configurar_fail2ban() {
    clear
    echo "*****************************"
    echo "*  Configuración de Fail2Ban (SSH)  *"
    echo "*****************************"
    echo "1. Configurar Fail2Ban para SSH"
    echo "2. Ver configuración actual de Fail2Ban"
    echo "3. Desactivar Fail2Ban"
    echo "4. Volver al menú principal"
    echo "*****************************"
    read -p "Selecciona una opción [1-4]: " opcion_fail2ban

    case $opcion_fail2ban in
        1)
            configurar_fail2ban_ssh
            ;;
        2)
            ver_configuracion_fail2ban
            ;;
        3)
            desactivar_fail2ban
            ;;
        4)
            return
            ;;
        *)
            echo "Opción inválida. Intenta de nuevo."
            ;;
    esac
    read -p "Presiona Enter para continuar..."
}

# Función para configurar Fail2Ban para SSH
configurar_fail2ban_ssh() {
    clear
    echo "*****************************"
    echo "*  Configuración de Fail2Ban para SSH  *"
    echo "*****************************"
    
    # Preguntar al usuario por las configuraciones personalizadas
    read -p "Introduce el tiempo de bloqueo (bantime) en segundos (Ej: 600): " bantime
    read -p "Introduce el tiempo en el que se cuentan los intentos fallidos (findtime) en segundos (Ej: 600): " findtime
    read -p "Introduce el número máximo de intentos fallidos (maxretry) antes de bloquear la IP (Ej: 3): " maxretry
    read -p "¿Quieres que el tiempo de bloqueo aumente progresivamente? (si/no): " incrementa_bantime

    if [ "$incrementa_bantime" == "si" ]; then
        read -p "Introduce el incremento del tiempo de bloqueo en segundos (Ej: 300): " incremento
        bantime_increment="bantime.increment = $incremento"
    else
        bantime_increment=""
    fi

    # Guardar configuración personalizada en el archivo jail.local
    cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime  = $bantime
findtime = $findtime
maxretry = $maxretry
$bantime_increment

[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = $maxretry
EOF

    # Reiniciar Fail2Ban para aplicar la configuración
    systemctl restart fail2ban
    echo "Fail2Ban configurado para proteger SSH con los siguientes parámetros:"
    echo "Bantime: $bantime segundos"
    echo "Findtime: $findtime segundos"
    echo "Maxretry: $maxretry intentos fallidos"
    if [ "$incrementa_bantime" == "si" ]; then
        echo "Incremento del bantime activado: $incremento segundos"
    else
        echo "Incremento del bantime desactivado."
    fi
    echo "La configuración ha sido aplicada y Fail2Ban ha sido reiniciado."
}

# Función para ver la configuración actual de Fail2Ban
ver_configuracion_fail2ban() {
    clear
    echo "*****************************"
    echo "*  Configuración Actual de Fail2Ban  *"
    echo "*****************************"
    
    # Ver la configuración actual de Fail2Ban
    cat /etc/fail2ban/jail.local
    echo "*****************************"
    echo "Estado actual de Fail2Ban:"
    fail2ban-client status
    echo "*****************************"
}

# Función para desactivar Fail2Ban
desactivar_fail2ban() {
    clear
    echo "*****************************"
    echo "*  Desactivando Fail2Ban  *"
    echo "*****************************"
    
    # Detener y deshabilitar el servicio Fail2Ban
    systemctl stop fail2ban
    systemctl disable fail2ban
    echo "Fail2Ban ha sido desactivado."
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 3 Limitar conexiones por IP (Prevención DDoS)
limitar_conexiones_ip() {
    read -p "Introduce el número máximo de conexiones por IP: " max_conexiones
    iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above $max_conexiones -j REJECT
    echo "Se ha limitado el número de conexiones por IP a $max_conexiones."
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 4 Escaneo de puertos abiertos
escaneo_puertos() {
    echo "Escaneando puertos abiertos..."
    netstat -tuln
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 5 Monitoreo de tráfico en tiempo real
monitoreo_trafico() {
    echo "Monitoreando tráfico en tiempo real..."
    iftop
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 6 Análisis de logs (SSH y Sistema)
analisis_logs() {
    echo "Análisis de logs de acceso SSH y sistema..."
    tail -n 100 /var/log/auth.log
    tail -n 100 /var/log/syslog
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 7 Función para escanear la red local
escaneo_red_local() {
    clear
    echo "*****************************"
    echo "* Escaneo de la Red Local  *"
    echo "*****************************"
    
    # Obtención de la dirección IP local y la máscara de subred
    ip_local=$(hostname -I | awk '{print $1}')
    red_local=$(echo $ip_local | cut -d '.' -f1-3)
    
    # Realizar escaneo de la red local con nmap
    echo "Escaneando dispositivos en la red local: $red_local.0/24"
    nmap -sn $red_local.0/24

    echo "Escaneo completado."
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 8 Función para escanear una red externa
escaneo_red_externa() {
    clear
    echo "*****************************"
    echo "* Escaneo de una Red Externa *"
    echo "*****************************"
    
    # Solicitar al usuario la IP o rango de IP a escanear
    read -p "Introduce la dirección IP o rango a escanear (Ej: 192.168.1.0/24 o 192.168.1.100-200): " red_externa
    
    # Realizar el escaneo con nmap
    echo "Escaneando la red externa: $red_externa"
    nmap -sn $red_externa

    echo "Escaneo completado."
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 9 Generación de Reporte de Seguridad
generar_reporte() {
    clear
    echo "Generando reporte de seguridad..."
    echo "Fecha: $(date)" > reporte_seguridad.txt
    echo "----------------------------" >> reporte_seguridad.txt
    echo "Estado de las reglas actuales del firewall:" >> reporte_seguridad.txt
    iptables -L >> reporte_seguridad.txt
    echo "----------------------------" >> reporte_seguridad.txt
    echo "Estado de Fail2Ban:" >> reporte_seguridad.txt
    fail2ban-client status sshd >> reporte_seguridad.txt
    echo "----------------------------" >> reporte_seguridad.txt
    echo "Últimos logs de SSH:" >> reporte_seguridad.txt
    tail -n 100 /var/log/auth.log >> reporte_seguridad.txt
    echo "----------------------------" >> reporte_seguridad.txt
    echo "Últimos logs del sistema:" >> reporte_seguridad.txt
    tail -n 100 /var/log/syslog >> reporte_seguridad.txt
    echo "----------------------------" >> reporte_seguridad.txt
    echo "Uso de Disco:" >> reporte_seguridad.txt
    df -h >> reporte_seguridad.txt
    echo "----------------------------" >> reporte_seguridad.txt
    echo "Uso de Memoria:" >> reporte_seguridad.txt
    free -h >> reporte_seguridad.txt
    echo "Reporte generado: reporte_seguridad.txt"
}

# Menú principal
while true; do
    mostrar_menu
    case $opcion in
        1)
            configurar_firewall
            ;;
        2)
            configurar_fail2ban
            ;;
        3)
            limitar_conexiones_ip
            ;;
        4)
            escaneo_puertos
            ;;
        5)
            monitoreo_trafico
            ;;
        6)
            analisis_logs
            ;;
        7)
            escaneo_red_local
            ;;
        8)
            escaneo_red_externa
            ;;
        9)
            generar_reporte
            ;;
        10)
            echo "Saliendo..."
            exit 0
            ;;
        *)
            echo "Opción inválida. Intenta de nuevo."
            ;;
    esac
    read -p "Presiona Enter para continuar..."
done
