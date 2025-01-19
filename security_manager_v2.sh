#!/bin/bash

# Comprobar si el script se está ejecutando como root
if [ "$(id -u)" -ne 0 ]; then
    echo "Este script debe ejecutarse como root o con sudo." 
    exit 1
fi

# Función para mostrar el menú principal
mostrar_menu() {
    clear
    echo "**********************************"
    echo "*  Gestión Avanzada de Seguridad *"
    echo "**********************************"
    echo "1. Configurar Firewall"
    echo "2. Configuración de Fail2Ban (SSH)"
    echo "3. Limitar Conexiones por IP (Prevención DDoS)"
    echo "4. Escaneo de Puertos Abiertos"
    echo "5. Monitoreo de Tráfico en Tiempo Real"
    echo "6. Análisis de Logs (SSH y Sistema)"
    echo "7. Escaneo de la Red Local"
    echo "8. Escaneo de una Red Externa"
    echo "9. Generar Reporte de Seguridad"
    echo "10. Hacer un escaneo de vulnerabilidades"
    echo "11. eliminar reglas del firewall"
    echo "12. Salir"
    echo "******************************"
    read -p "Selecciona una opción [1-12]: " opcion
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 1 Función para configurar el firewall

configurar_firewall() {
    while true; do
    clear
    echo "********************************"
    echo "*  Configuración del Firewall  *"
    echo "********************************"
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
    done
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
        sudo iptables -A INPUT -p $tipo --dport $puerto -j ACCEPT
        echo "Tráfico en el puerto $puerto permitido ($tipo)."
    
    
}


# Bloquear completamente una IP (incluido ping)
bloquear_ip() {
    read -p "Introduce la IP a bloquear: " ip

    # Bloquear el tráfico de esa IP en todas las cadenas (INPUT, OUTPUT, FORWARD)
    iptables -A INPUT -s $ip -j DROP
    iptables -A OUTPUT -d $ip -j DROP
    iptables -A FORWARD -s $ip -j DROP
    iptables -A FORWARD -d $ip -j DROP

    # Bloquear el ping (ICMP) de la IP
    iptables -A INPUT -p icmp --src $ip -j DROP
    iptables -A OUTPUT -p icmp --dst $ip -j DROP

    echo "La IP $ip ha sido completamente bloqueada (incluido ping)."
}


# Permitir tráfico de una IP específica (comprobando si está bloqueada)
permitir_ip() {
    read -p "Introduce la IP a permitir: " ip

    # Comprobar si la IP está bloqueada (buscar reglas de DROP para esta IP)
    bloqueo_ip=$(iptables -L INPUT -v -n | grep -w "DROP" | grep -w "$ip")
    
    if [ -n "$bloqueo_ip" ]; then
        # Si la IP está bloqueada, mostrar advertencia
        read -p "¡Advertencia! La IP $ip está bloqueada. ¿Seguro que quieres permitirla? (si/no): " respuesta
        if [ "$respuesta" == "si" ]; then
            # Eliminar las reglas de bloqueo para esa IP
            iptables -D INPUT -s $ip -j DROP
            iptables -D OUTPUT -d $ip -j DROP
            iptables -D FORWARD -s $ip -j DROP
            iptables -D FORWARD -d $ip -j DROP
            iptables -D INPUT -p icmp --src $ip -j DROP
            iptables -D OUTPUT -p icmp --dst $ip -j DROP

            echo "La regla de bloqueo para la IP $ip ha sido eliminada."
        else
            echo "La IP $ip no ha sido modificada. El tráfico sigue bloqueado."
            return
        fi
    fi

    # Permitir el tráfico de la IP
    iptables -A INPUT -s $ip -j ACCEPT
    iptables -A OUTPUT -d $ip -j ACCEPT
    iptables -A FORWARD -s $ip -j ACCEPT
    iptables -A FORWARD -d $ip -j ACCEPT

    # Permitir el ping (ICMP) hacia y desde la IP
    iptables -A INPUT -p icmp --src $ip -j ACCEPT
    iptables -A OUTPUT -p icmp --dst $ip -j ACCEPT

    echo "La IP $ip ha sido permitida y todo el tráfico ha sido aceptado."
}


# Permitir tráfico de un rango de IPs
permitir_rango_ip() {
    read -p "Introduce el rango de IPs a permitir (Ej: 192.168.1.0/24): " rango
    iptables -A INPUT -s $rango -j ACCEPT
    echo "El rango de IPs $rango ha sido permitido."
}

# Ver reglas actuales del firewall (solo las importantes)
ver_reglas_firewall() {
    echo "**************************************"
    echo "* Reglas de Firewall (ACCEPT y DROP) *"
    echo "**************************************"
    
    # Mostrar solo las reglas importantes: ACCEPT, DROP, y otras necesarias
    iptables -L INPUT -v -n | grep -E "ACCEPT|DROP|RELATED|ESTABLISHED"
    iptables -L FORWARD -v -n | grep -E "ACCEPT|DROP|RELATED|ESTABLISHED"
    iptables -L OUTPUT -v -n | grep -E "ACCEPT|DROP|RELATED|ESTABLISHED"
    
    echo "*************************************"
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# 2 Función para mostrar el menú de configuración de Fail2Ban
configurar_fail2ban() {
    while true; do
    clear
    echo "*************************************"
    echo "*  Configuración de Fail2Ban (SSH)  *"
    echo "*************************************"
    echo "1. Configurar Fail2Ban para SSH"
    echo "2. Ver configuración actual de Fail2Ban"
    echo "3. Desactivar Fail2Ban"
    echo '4. Desbanear una ip'
    echo '5. ver ips bloqueadas'
    echo "6. Volver al menú principal"
    echo "*************************************"
    read -p "Selecciona una opción [1-6]: " opcion_fail2ban

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
            read -p 'introduce la ip a desbloquear: ' ip
            sudo fail2ban-client set sshd unbanip $ip
        ;;
        5)
        sudo fail2ban-client status sshd
        ;;
        6)
            return
            ;;
        *)
            echo "Opción inválida. Intenta de nuevo."
            ;;
    esac
    read -p "Presiona Enter para continuar..."
    done
}

# Función para configurar Fail2Ban para SSH
configurar_fail2ban_ssh() {
    clear
    echo "****************************************"
    echo "*  Configuración de Fail2Ban para SSH  *"
    echo "****************************************"
    
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
    echo "**************************************"
    echo "*  Configuración Actual de Fail2Ban  *"
    echo "**************************************"
    
    # Ver la configuración actual de Fail2Ban
    cat /etc/fail2ban/jail.local
    echo "**************************************"
    echo "Estado actual de Fail2Ban:"
    fail2ban-client status
    echo "**************************************"
}

# Función para desactivar Fail2Ban
desactivar_fail2ban() {
    clear
    echo "***************************"
    echo "*  Desactivando Fail2Ban  *"
    echo "***************************"
    
    # Detener y deshabilitar el servicio Fail2Ban
    systemctl stop fail2ban
    systemctl disable fail2ban
    echo "Fail2Ban ha sido desactivado."
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 3 Limitar conexiones por IP (Prevención DDoS)
mitigar_ddos() {
    echo "Configuración interactiva para mitigación de DDoS"
    echo "-----------------------------------------------"

    # 1. Limitar conexiones por IP
    read -p "¿Deseas limitar el número de conexiones simultáneas por IP? (s/n): " limit_ip
    if [[ "$limit_ip" == "s" ]]; then
        read -p "Introduce el número máximo de conexiones simultáneas por IP (ej. 10): " max_conexiones
        iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above "$max_conexiones" --connlimit-mask 32 -j DROP
        echo "Se ha configurado un límite de $max_conexiones conexiones por IP."
    fi

    # 2. Limitar tasa global de paquetes SYN
    read -p "¿Deseas limitar la tasa de paquetes SYN global? (s/n): " limit_syn
    if [[ "$limit_syn" == "s" ]]; then
        read -p "Introduce la tasa máxima de paquetes SYN por segundo (ej. 50): " syn_rate
        read -p "Introduce el burst inicial permitido (ej. 100): " syn_burst
        iptables -A INPUT -p tcp --syn -m limit --limit "$syn_rate"/second --limit-burst "$syn_burst" -j ACCEPT
        iptables -A INPUT -p tcp --syn -j DROP
        echo "Se ha configurado una tasa de $syn_rate paquetes SYN/segundo con un burst inicial de $syn_burst."
    fi

    # 3. Limitar conexiones HTTP
    read -p "¿Deseas limitar el número de conexiones HTTP por IP? (s/n): " limit_http
    if [[ "$limit_http" == "s" ]]; then
        read -p "Introduce el número máximo de conexiones HTTP por IP (ej. 20): " max_http
        iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above "$max_http" --connlimit-mask 32 -j DROP
        echo "Se ha configurado un límite de $max_http conexiones HTTP por IP."
    fi

    # 4. Bloquear paquetes inválidos
    read -p "¿Deseas bloquear paquetes inválidos? (s/n): " block_invalid
    if [[ "$block_invalid" == "s" ]]; then
        iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
        echo "Se han bloqueado paquetes inválidos."
    fi

    # 5. Limitar tráfico UDP
    read -p "¿Deseas limitar la tasa de tráfico UDP? (s/n): " limit_udp
    if [[ "$limit_udp" == "s" ]]; then
        read -p "Introduce la tasa máxima de paquetes UDP por segundo (ej. 10): " udp_rate
        read -p "Introduce el burst inicial permitido para UDP (ej. 20): " udp_burst
        iptables -A INPUT -p udp -m limit --limit "$udp_rate"/second --limit-burst "$udp_burst" -j ACCEPT
        iptables -A INPUT -p udp -j DROP
        echo "Se ha configurado una tasa de $udp_rate paquetes UDP/segundo con un burst inicial de $udp_burst."
    fi

    # 6. Protección contra ping flood
    read -p "¿Deseas proteger contra ping flood (ICMP)? (s/n): " limit_icmp
    if [[ "$limit_icmp" == "s" ]]; then
        read -p "Introduce la tasa máxima de solicitudes de eco (ping) por segundo (ej. 10): " icmp_rate
        read -p "Introduce el burst inicial permitido para ICMP (ej. 20): " icmp_burst
        iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit "$icmp_rate"/second --limit-burst "$icmp_burst" -j ACCEPT
        iptables -A INPUT -p icmp -j DROP
        echo "Se ha configurado una tasa de $icmp_rate pings/segundo con un burst inicial de $icmp_burst."
    fi

    echo "Configuración de mitigación de DDoS completada. Verifica con 'iptables -L -n -v'."
    echo "Presiona Enter para continuar..."
    read
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
# Función para análisis de logs - Simple
analizar_logs_simple() {
    clear
    echo "*****************************"
    echo "* Análisis de Logs - Simple *"
    echo "*****************************"
    echo "Logs más importantes:"
    
    # Verificar los logs más importantes (por ejemplo, auth.log, syslog, dmesg)
    echo -e "\n--- Últimos registros de autenticación (auth.log) ---"
    tail -n 20 /var/log/auth.log
    
    echo -e "\n--- Últimos registros del sistema (syslog) ---"
    tail -n 20 /var/log/syslog
    
    echo -e "\n--- Últimos registros de errores del kernel (dmesg) ---"
    dmesg | tail -n 20

    echo -e "\n--- Últimos registros de Fail2Ban ---"
    tail -n 20 /var/log/fail2ban.log
    
    echo "****************************"
    echo "Análisis completado (resumen)."
    echo "****************************"
}
# Función para análisis de logs - Avanzado
analizar_logs_avanzado() {
    clear
    echo "*******************************"
    echo "* Análisis de Logs - Avanzado *"
    echo "*******************************"
    echo "Mostrando todos los logs disponibles en el sistema..."

    # Ver todos los logs posibles (debe tener permisos de administrador)
    echo -e "\n--- Logs de autenticación (auth.log) ---"
    cat /var/log/auth.log

    echo -e "\n--- Logs del sistema (syslog) ---"
    cat /var/log/syslog

    echo -e "\n--- Logs del kernel (dmesg) ---"
    dmesg

    echo -e "\n--- Logs de Fail2Ban ---"
    cat /var/log/fail2ban.log
    
    echo -e "\n--- Logs de Apache (si se utiliza) ---"
    cat /var/log/apache2/access.log
    cat /var/log/apache2/error.log

    echo -e "\n--- Logs de Nginx (si se utiliza) ---"
    cat /var/log/nginx/access.log
    cat /var/log/nginx/error.log

    echo "******************************"
    echo "Análisis completado (avanzado)."
    echo "******************************"
}

#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 7 Función para escanear la red local
escaneo_red_local() {
 
# Obtener la dirección IP y máscara de subred
network=$(ip -o -f inet addr show | awk '/scope global/ {print $4}')

if [ -z "$network" ]; then
    echo "No se pudo determinar la red automáticamente."
    exit 1
fi

# Ejecutar netdiscover con el rango de red detectado
echo "Ejecutando netdiscover en la red: $network"
netdiscover -r "$network"

}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 8 Función para escanear una red externa
escaneo_red_externa() {
    clear
    echo "******************************"
    echo "* Escaneo de una Red Externa *"
    echo "******************************"
    
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
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# 10 Función para escanear el sistema en busca de vulnerabilidades
escanear_vulnerabilidades() {
    clear
    echo "*******************************************"
    echo "* Escaneo de Vulnerabilidades del Sistema *"
    echo "*******************************************"

    # Ejecutar Lynis para realizar una auditoría de seguridad
    lynis audit system > lynis_report.txt

    echo "Escaneo completado. El informe se ha guardado en lynis_report.txt."
    echo "*****************************"
    echo "El informe de vulnerabilidades puede ser revisado en el archivo 'lynis_report.txt'."
}
#------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#11 eliminar reglas
# Función para eliminar reglas de la cadena INPUT
eliminar_reglas_input() {
    echo "*********************************"
    echo "*   Eliminar Reglas de INPUT    *"
    echo "*********************************"
    
    # Mostrar las reglas numeradas de INPUT
    sudo iptables -L INPUT --line-numbers -n
    
    # Solicitar al usuario el número de regla a eliminar
    read -p "Introduce el número de la regla a eliminar: " regla_num

    # Validar si el número de regla es válido
    if [[ ! "$regla_num" =~ ^[0-9]+$ ]]; then
        echo "El número de la regla no es válido."
        return
    fi

    # Eliminar la regla especificada
    sudo iptables -D INPUT $regla_num
    echo "Se ha eliminado la regla número $regla_num en la cadena INPUT."

    # Preguntar si desea eliminar más reglas de la cadena INPUT
    read -p "¿Quieres eliminar alguna más de INPUT? (s/n): " continuar
    if [[ "$continuar" == "s" ]]; then
        eliminar_reglas_input  # Llamada recursiva para eliminar más reglas
    fi
}

# Función para eliminar reglas de la cadena OUTPUT
eliminar_reglas_output() {
    echo "*********************************"
    echo "*   Eliminar Reglas de OUTPUT   *"
    echo "*********************************"
    
    # Mostrar las reglas numeradas de OUTPUT
    sudo iptables -L OUTPUT --line-numbers -n
    
    # Solicitar al usuario el número de regla a eliminar
    read -p "Introduce el número de la regla a eliminar: " regla_num

    # Validar si el número de regla es válido
    if [[ ! "$regla_num" =~ ^[0-9]+$ ]]; then
        echo "El número de la regla no es válido."
        return
    fi

    # Eliminar la regla especificada
    sudo iptables -D OUTPUT $regla_num
    echo "Se ha eliminado la regla número $regla_num en la cadena OUTPUT."

    # Preguntar si desea eliminar más reglas de la cadena OUTPUT
    read -p "¿Quieres eliminar alguna más de OUTPUT? (s/n): " continuar
    if [[ "$continuar" == "s" ]]; then
        eliminar_reglas_output  # Llamada recursiva para eliminar más reglas
    fi
}

# Función para eliminar reglas de la cadena FORWARD
eliminar_reglas_forward() {
    echo "*********************************"
    echo "*   Eliminar Reglas de FORWARD  *"
    echo "*********************************"
    
    # Mostrar las reglas numeradas de FORWARD
    sudo iptables -L FORWARD --line-numbers -n
    
    # Solicitar al usuario el número de regla a eliminar
    read -p "Introduce el número de la regla a eliminar: " regla_num

    # Validar si el número de regla es válido
    if [[ ! "$regla_num" =~ ^[0-9]+$ ]]; then
        echo "El número de la regla no es válido."
        return
    fi

    # Eliminar la regla especificada
    sudo iptables -D FORWARD $regla_num
    echo "Se ha eliminado la regla número $regla_num en la cadena FORWARD."

    # Preguntar si desea eliminar más reglas de la cadena FORWARD
    read -p "¿Quieres eliminar alguna más de FORWARD? (s/n): " continuar
    if [[ "$continuar" == "s" ]]; then
        eliminar_reglas_forward  # Llamada recursiva para eliminar más reglas
    fi
}

# Función principal para eliminar reglas
eliminar_reglas() {
    clear
    echo "************************************"
    echo "*   Eliminar Reglas del Firewall   *"
    echo "************************************"
    sudo iptables -L --line-numbers -n
    # Preguntar al usuario qué tipo de cadena desea modificar
    read -p "¿Quieres eliminar reglas de INPUT (1), FORWARD (2) o OUTPUT (3)? [1-3]: " opcion
    if [[ ! "$opcion" =~ ^[1-3]$ ]]; then
        echo "Opción no válida. Elige 1, 2 o 3."
        return
    fi

    # Llamar a la función correspondiente según la opción
    case $opcion in
        1)
            eliminar_reglas_input
            ;;
        3)
            eliminar_reglas_output
            ;;
        2)
            eliminar_reglas_forward
            ;;
    esac

    # Guardar las reglas de iptables para que se mantengan después del reinicio
    sudo netfilter-persistent save
    echo "Se han guardado las reglas de iptables para que sean persistentes."
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
            mitigar_ddos
            ;;
        4)
            escaneo_puertos
            ;;
        5)
            monitoreo_trafico
            ;;
        6)
            echo "1. Análisis Simple de Logs"
            echo "2. Análisis Avanzado de Logs"
            read -p "Selecciona una opción [1-2]: " opcion_logs
            case $opcion_logs in
                1)
                    analizar_logs_simple
                    ;;
                2)
                    analizar_logs_avanzado
                    ;;
                *)
                    echo "Opción inválida."
                    ;;
            esac
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
            escanear_vulnerabilidades
            ;;
        11)
            eliminar_reglas
            ;;
        12)
            read -p 'antes de salir, quieres hacer persistentes las reglas creadas?(s/n)' reglas
            if [ "$reglas" == "s" ]; then
            sudo netfilter-persistent save
            fi

            echo "Saliendo..."
            exit 0
            ;;
        *)
            echo "Opción inválida. Intenta de nuevo."
            ;;
    esac
    read -p "Presiona Enter para continuar..."
done
