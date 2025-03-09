#!/usr/bin/env python3

import os
import subprocess
import re
import shlex

# Comprobar si el script se está ejecutando como root
if os.geteuid() != 0:
    print("Este script debe ejecutarse como root o con sudo.")
    exit(1)

# Función para mostrar el menú principal


# Funciones para cada opción del menú
def configurar_firewall():
    while True:
        os.system('clear')
        
        print("********************************")
        print("*  Configuración del Firewall  *")
        print("********************************")
        print("1. Configuración inicial")
        print("2. Reglas de puertos")
        print("3. Bloquear tráfico de una IP específica")
        print("4. Permitir tráfico de una IP específica")
        print("5. Permitir tráfico en un rango de IPs")
        print("6. Bloquear tráfico en un rango de IPs")
        print("7. Ver reglas actuales del firewall")
        print("8. Limpiar todas las reglas del firewall")
        print("9. Eliminar reglas concretas del firewall")
        print("10. Volver")
        print("*****************************")
        opcion_firewall = input("Selecciona una opción [1-10]: ")
        
        if opcion_firewall == '1':
            configuracion_inicial()
        elif opcion_firewall == '2':
            reglas_de_puertos()
        elif opcion_firewall == '3':
            bloquear_ip()
        elif opcion_firewall == '4':
            permitir_ip()
        elif opcion_firewall == '5':
            permitir_rango_ip()
        elif opcion_firewall == '6':
            denegar_rango_ip()
        elif opcion_firewall == '7':
            ver_reglas_firewall()
            input("Presiona Enter para continuar...")
        elif opcion_firewall == '8':
            limpiar_reglas()
            input("Presiona Enter para continuar...")
        elif opcion_firewall == '9':
            eliminar_reglas()
        elif opcion_firewall == '10':
            optimizar_firewall()
            return
        else:
            print("Opción inválida. Intenta de nuevo.")
        input("Presiona Enter para continuar...")
        optimizar_firewall()
        

def configuracion_inicial():
    print("Iniciando configuración del firewall...")
    
    # Limpiar reglas existentes antes de aplicar nuevas
    subprocess.run(["iptables", "-F"], check=True)
    subprocess.run(["iptables", "-X"], check=True)
    subprocess.run(["iptables", "-Z"], check=True)
    
    # Preguntar si el usuario está conectado por SSH
    conectado_ssh = input("¿Estás conectado por SSH? (si/no): ").strip().lower()
    
    if conectado_ssh == "si":
        # Obtener la IP del usuario conectado por SSH
        ip_ssh = os.environ.get("SSH_CLIENT", "").split()[0] if "SSH_CLIENT" in os.environ else ""
        
        if not ip_ssh:
            print("No se pudo detectar la IP de la sesión SSH.")
            os.system("who")
            ip_ssh = input("Introduce manualmente tu IP SSH: ").strip()
        
        print(f"Detectada conexión SSH desde: {ip_ssh}")
        
        # Permitir SSH desde esta IP
        subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "-s", ip_ssh, "--dport", "22", "-j", "ACCEPT"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-d", ip_ssh, "-j", "ACCEPT"], check=True)
    
    # Permitir tráfico de loopback (localhost)
    subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
    subprocess.run(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
    
    # Permitir tráfico ya establecido y relacionado
    subprocess.run(["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)
    subprocess.run(["iptables", "-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)
    
    # Permitir consultas DNS (para resolver dominios)
    subprocess.run(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"], check=True)
    subprocess.run(["iptables", "-A", "INPUT", "-p", "udp", "--sport", "53", "-j", "ACCEPT"], check=True)
    
    # Permitir tráfico HTTP y HTTPS (para poder navegar y actualizar paquetes)
    subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "ACCEPT"], check=True)
    subprocess.run(["iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "ACCEPT"], check=True)
    subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--sport", "80", "-j", "ACCEPT"], check=True)
    subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--sport", "443", "-j", "ACCEPT"], check=True)
    
    # Permitir ping (ICMP)
    subprocess.run(["iptables", "-A", "INPUT", "-p", "icmp", "-j", "ACCEPT"], check=True)
    subprocess.run(["iptables", "-A", "OUTPUT", "-p", "icmp", "-j", "ACCEPT"], check=True)
    
    # Bloquear todo el tráfico no permitido explícitamente
    subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
    subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=True)
    subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=True)
    
    print("Configuración inicial del firewall aplicada.")


def reglas_de_puertos():
    while True:
        os.system('clear')
        print("********************************")
        print("*       reglas de puertos      *")
        print("********************************")
        print("1. Permitir el trafico en un puerto o rango de puertos")
        print("2. Denegar el trafico en un puerto o rango de puertos")
        print("3. vorlver")
        print("*****************************")
        opcion_puertos = input("Selecciona una opción [1-3]: ")

        if opcion_puertos == '1':
            permitir_puerto()
        elif opcion_puertos == '2':
            cerrar_puerto()
        elif opcion_puertos == '3':
            return
        else:
            print("Opción inválida. Intenta de nuevo.")
        optimizar_firewall()
    
#-------------------------------------------------------------------------------------------------------------------------------------------------------

def ejecutar_comando(comando):
    """Ejecuta un comando en la terminal y devuelve la salida."""
    try:
        resultado = subprocess.run(comando, shell=True, text=True, capture_output=True)
        return resultado.stdout.strip()
    except Exception as e:
        print(f"Error ejecutando el comando: {e}")
        return None
    
    
#-------------------------------------------------------------------------------------------------------------------------------------------------------


def regla_existente_puerto(cadena, protocolo, puerto, direccion):
    """Verifica si una regla ya existe en iptables utilizando una búsqueda precisa."""
    reglas = ejecutar_comando("sudo iptables-save")
    if reglas:
        # Ajustamos el patrón para que coincida con la salida exacta de iptables-save
        if direccion == "dport":
            patron = rf"-A {cadena} -p {protocolo} -m {protocolo} --dport {puerto} -j ACCEPT"
        else:  # Para sport
            patron = rf"-A {cadena} -p {protocolo} -m {protocolo} --sport {puerto} -j ACCEPT"

        if re.search(patron, reglas):
            print(f"✅ Regla encontrada para {protocolo.upper()} en {direccion.upper()} {puerto}.")
            return True
        else:
            print(f"🚫 No se encontró la regla exacta con el patrón: {patron}")
    return False

#-------------------------------------------------------------------------------------------------------------------------------------------------------

def permitir_puerto():
    puerto = input("Introduce el número de puerto o rang de puertos a permitir (Ej: 8080 o 8000:8080): ")
    tipo = input("¿Deseas permitir tráfico TCP, UDP o ambos? (tcp/udp/ambos): ").lower()
    direccion = input("¿Deseas permitir tráfico entrante, saliente o ambos? (entrante/saliente/ambos): ").lower()

    tipos = []
    if tipo == "tcp":
        tipos.append("tcp")
    elif tipo == "udp":
        tipos.append("udp")
    elif tipo == "ambos":
        tipos = ["tcp", "udp"]
    else:
        print("Opción no válida. Debes elegir entre 'tcp', 'udp' o 'ambos'.")
        return

    direcciones = []
    if direccion == "entrante":
        direcciones.append("dport")
    elif direccion == "saliente":
        direcciones.append("sport")
    elif direccion == "ambos":
        direcciones = ["dport", "sport"]
    else:
        print("Opción no válida. Debes elegir entre 'entrante', 'saliente' o 'ambos'.")
        return

    for tipo in tipos:
        for dir_flag in direcciones:
            cadena = "INPUT" if dir_flag == "dport" else "OUTPUT"
            if regla_existente_puerto(cadena, tipo, puerto, dir_flag):
                print(f"La regla para {tipo} en el puerto {puerto} ({direccion}) ya existe.")
            else:
                comando = f"sudo iptables -I {cadena} 1 -p {tipo} --{dir_flag} {puerto} -j ACCEPT"
                ejecutar_comando(comando)
                print(f"Regla agregada: {tipo.upper()} {direccion.upper()} en el puerto {puerto}")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

def cerrar_puerto():
    puerto = input("Introduce el número de puerto o rango de puertos a cerrar (Ej: 8080 o 8000:8080): ")
    tipo = input("¿Deseas cerrar tráfico TCP, UDP o ambos? (tcp/udp/ambos): ").lower()
    direccion = input("¿Deseas cerrar tráfico entrante, saliente o ambos? (entrante/saliente/ambos): ").lower()

    tipos = []
    if tipo == "tcp":
        tipos.append("tcp")
    elif tipo == "udp":
        tipos.append("udp")
    elif tipo == "ambos":
        tipos = ["tcp", "udp"]
    else:
        print("Opción no válida. Debes elegir entre 'tcp', 'udp' o 'ambos'.")
        return

    direcciones = []
    if direccion == "entrante":
        direcciones.append("dport")
    elif direccion == "saliente":
        direcciones.append("sport")
    elif direccion == "ambos":
        direcciones = ["dport", "sport"]
    else:
        print("Opción no válida. Debes elegir entre 'entrante', 'saliente' o 'ambos'.")
        return

    for tipo in tipos:
        for dir_flag in direcciones:
            cadena = "INPUT" if dir_flag == "dport" else "OUTPUT"
            if regla_existente_puerto(cadena, tipo, puerto, dir_flag):
                comando = f"sudo iptables -D {cadena} -p {tipo} --{dir_flag} {puerto} -j ACCEPT"
                ejecutar_comando(comando)
                print(f"Regla eliminada: {tipo.upper()} {direccion.upper()} en el puerto {puerto}")
            else:
                print(f"No existe una regla para {tipo} en el puerto {puerto} ({direccion}).")


#-------------------------------------------------------------------------------------------------------------------------------------------------------


def ip_bloqueada(ip):
    """Verifica si una IP está bloqueada en iptables."""
    try:
        resultado = subprocess.run(
            ["sudo", "iptables", "-L", "INPUT", "-v", "-n"],
            capture_output=True, text=True, check=True
        )
        
        # Buscar la IP en las reglas que contienen "DROP"
        for linea in resultado.stdout.splitlines():
            if "DROP" in linea and ip in linea:
                return True
        return False

    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar iptables: {e}")
        return False
    


#-------------------------------------------------------------------------------------------------------------------------------------------------------



def ip_permitida(ip):
    """Verifica si una IP está permitida en iptables."""
    try:
        resultado = subprocess.run(
            ["sudo", "iptables", "-L", "INPUT", "-v", "-n"],
            capture_output=True, text=True, check=True
        )
        
        # Buscar la IP en las reglas que contienen "ACCEPT"
        for linea in resultado.stdout.splitlines():
            if "ACCEPT" in linea and ip in linea:
                return True
        return False

    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar iptables: {e}")
        return False
    


#-------------------------------------------------------------------------------------------------------------------------------------------------------


def bloquear_ip():
    """Bloquea completamente una IP en iptables, incluyendo ping."""
    ip = input("Introduce la IP a bloquear: ").strip()

    # Eliminar reglas de aceptación para evitar conflictos
    if ip_permitida(ip):
        print(f"Eliminando reglas de aceptación existentes para la IP {ip}...")
        comandos_eliminar = [
            [f"sudo iptables -D INPUT -s {ip} -j ACCEPT"],
            [f"sudo iptables -D OUTPUT -d {ip} -j ACCEPT"],
            [f"sudo iptables -D FORWARD -s {ip} -j ACCEPT"],
            [f"sudo iptables -D FORWARD -d {ip} -j ACCEPT"],
            [f"sudo iptables -D INPUT -p icmp --src {ip} -jACCEPT"],
            [f"sudo iptables -D OUTPUT -p icmp --dst {ip} -j ACCEPT"],
        ]
        for comando in comandos_eliminar:
            ejecutar_comando(comando)

    # Validar si la IP ya está bloqueada
    if ip_bloqueada(ip):
        print(f"La IP {ip} ya ha sido bloqueada")
        return

    # Bloquear el tráfico de la IP en todas las cadenas (INPUT, OUTPUT, FORWARD)
    respuesta = input("Quiere agregar relgas de denegacion, o le vale con eliminar las de aceptacion? (si/no): ")
    if respuesta.lower() == "si":
        comandos_bloqueo = [
            [f"sudo iptables -I INPUT 1 -s {ip} -j DROP"],
            [f"sudo iptables -I OUTPUT 1 -d {ip} -j DROP"],
            [f"sudo iptables -I FORWARD 1 -s {ip} -j DROP"],
            [f"sudo iptables -I FORWARD 1 -d {ip} -j DROP"],
            [f"sudo iptables -I INPUT 1 -p icmp --src {ip} -j DROP"],
            [f"sudo iptables -I OUTPUT 1 -p icmp --dst {ip} -j DROP"],

        ]
        for comando in comandos_bloqueo:
            ejecutar_comando(comando)

    print(f"La IP {ip} ha sido completamente bloqueada (incluido ping).")


#-------------------------------------------------------------------------------------------------------------------------------------------------------


def permitir_ip():
    """Permitir tráfico de una IP específica (comprobando si está bloqueada)"""
    ip = input("Introduce la IP a permitir: ").strip()

    if ip_bloqueada(ip):
        respuesta = input(f"¡Advertencia! La IP {ip} está bloqueada. ¿Quieres eliminar las reglas de bloqueo y permitirla? (si/no): ")
        if respuesta.lower() != "si":
            print(f"La IP {ip} no ha sido modificada. El tráfico sigue bloqueado.")
            return
        comandos_eliminar = [
            [f"iptables -D INPUT -s {ip} -j DROP"],
            [f"iptables -D OUTPUT -d {ip} -j DROP"],
            [f"iptables -D FORWARD -s {ip} -j DROP"],
            [f"iptables -D FORWARD -d {ip} -j DROP"],
            [f"iptables -D INPUT -p icmp --src {ip} -j DROP"],
            [f"iptables -D OUTPUT -p icmp --dst {ip} -j DROP"],
        ]
        for comando in comandos_eliminar:
            ejecutar_comando(comando)

    # Validar si la IP ya está bloqueada
    if ip_permitida(ip):
        print(f"La IP {ip} ya ha sido permitida")
        return



    # Bloquear el tráfico de la IP en todas las cadenas (INPUT, OUTPUT, FORWARD)
    comandos_ACCEPT = [
        [f"sudo iptables -I INPUT 1 -s {ip} -j ACCEPT"],
        [f"sudo iptables -I OUTPUT 1 -d {ip} -j ACCEPT"],
        [f"sudo iptables -I FORWARD 1 -s {ip} -j ACCEPT"],
        [f"sudo iptables -I FORWARD 1 -d {ip} -j ACCEPT"],
        [f"sudo iptables -I INPUT 1 -p icmp --src {ip} -j ACCEPT"],
        [f"sudo iptables -I OUTPUT 1 -p icmp --dst {ip} -j ACCEPT"],

    ]
    for comando in comandos_ACCEPT:
        ejecutar_comando(comando)

    print(f"La IP {ip} ha sido completamente permitida (incluido ping).")


#-------------------------------------------------------------------------------------------------------------------------------------------------------


def permitir_rango_ip():
    """Permitir tráfico de un rango de IPs (comprobando si está permitido)"""
    rango = input("Introduce el rango de IPs a permitir (Ej: 192.168.1.0/24): ").strip()

    if ip_bloqueada(rango):
        respuesta = input(f"¡Advertencia! El rango de IPs {rango} está bloqueado. ¿Quieres eliminar las reglas de bloqueo y permitirlo? (si/no): ")
        if respuesta.lower() != "si":
            print(f"La IP {rango} no ha sido modificada. El tráfico sigue bloqueado.")
            return
        comandos_eliminar = [
            [f"iptables -D INPUT -s {rango} -j DROP"],
            [f"iptables -D OUTPUT -d {rango} -j DROP"],
            [f"iptables -D FORWARD -s {rango} -j DROP"],
            [f"iptables -D FORWARD -d {rango} -j DROP"],
            [f"iptables -D INPUT -p icmp --src {rango} -j DROP"],
            [f"iptables -D OUTPUT -p icmp --dst {rango} -j DROP"],
        ]
        for comando in comandos_eliminar:
            ejecutar_comando(comando)

    # Validar si la IP ya está bloqueada
    if ip_permitida(rango):
        print(f"el rango de IPs {rango} ya ha sido permitido")
        return



    # Bloquear el tráfico de la IP en todas las cadenas (INPUT, OUTPUT, FORWARD)
    comandos_ACCEPT = [
        [f"sudo iptables -I INPUT 1 -s {rango} -j ACCEPT"],
        [f"sudo iptables -I OUTPUT 1 -d {rango} -j ACCEPT"],
        [f"sudo iptables -I FORWARD 1 -s {rango} -j ACCEPT"],
        [f"sudo iptables -I FORWARD 1 -d {rango} -j ACCEPT"],
        [f"sudo iptables -I INPUT -p icmp --src {rango} -j ACCEPT"],
        [f"sudo iptables -I OUTPUT -p icmp --dst {rango} -j ACCEPT"],
    ]
    for comando in comandos_ACCEPT:
        ejecutar_comando(comando)

    print(f"El rango de IPs {rango} ha sido completamente permitido.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

def denegar_rango_ip():
    """denegar tráfico de un rango de IPs (comprobando si está permitido)"""
    rango = input("Introduce el rango de IPs a denegar (Ej: 192.168.1.0/24): ").strip()

    if ip_permitida(rango):
        respuesta = input(f"¡Advertencia! El rango de IPs {rango} está permidido. ¿Quieres eliminar las reglas de permiso y bloquearlo? (si/no): ")
        if respuesta.lower() != "si":
            print(f"La IP {rango} no ha sido modificada. El tráfico sigue bloqueado.")
            return
        comandos_eliminar = [
            [f"iptables -D INPUT -s {rango} -j ACCEPT"],
            [f"iptables -D OUTPUT -d {rango} -j ACCEPT"],
            [f"iptables -D FORWARD -s {rango} -j ACCEPT"],
            [f"iptables -D FORWARD -d {rango} -j ACCEPT"],
            [f"iptables -D INPUT -p icmp --src {rango} -j ACCEPT"],
            [f"iptables -D OUTPUT -p icmp --dst {rango} -j ACCEPT"],
        ]
        for comando in comandos_eliminar:
            ejecutar_comando(comando)

    # Validar si la IP ya está bloqueada
    if ip_bloqueada(rango):
        print(f"el rango de IPs {rango} ya ha sido bloqueado")
        return


    respuesta = input("Quiere agregar relgas de denegacion, o le vale con eliminar las de aceptacion? (si/no): ")
    if respuesta.lower() == "si":
        # Bloquear el tráfico de la IP en todas las cadenas (INPUT, OUTPUT, FORWARD)
        comandos_ACCEPT = [
            [f"sudo iptables -I INPUT 1 -s {rango} -j DROP"],
            [f"sudo iptables -I OUTPUT 1 -d {rango} -j DROP"],
            [f"sudo iptables -I FORWARD 1 -s {rango} -j DROP"],
            [f"sudo iptables -I FORWARD 1 -d {rango} -j DROP"],
            [f"sudo iptables -I INPUT -p icmp --src {rango} -j DROP"],
            [f"sudo iptables -I OUTPUT -p icmp --dst {rango} -j DROP"],
        ]
        for comando in comandos_ACCEPT:
            ejecutar_comando(comando)

    print(f"El rango de IPs {rango} ha sido completamente bloqueado.")


#-------------------------------------------------------------------------------------------------------------------------------------------------------


def ver_reglas_firewall():
    # Implementar la función para ver las reglas actuales del firewall
    print("**************************************")
    print("* Reglas de Firewall (ACCEPT y DROP) *")
    print("**************************************")
    
    # Mostrar solo las reglas importantes: ACCEPT, DROP, y otras necesarias
    for chain in ['INPUT', 'FORWARD', 'OUTPUT']:
        print(f"\nReglas para la cadena {chain}:")
        try:
            result = subprocess.run(
                f"iptables -L {chain} -v -n | grep -E 'ACCEPT|DROP|RELATED|ESTABLISHED'",
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print(result.stdout.decode())
        except subprocess.CalledProcessError:
            print(f"No se pudieron obtener las reglas para la cadena {chain}.")
    
    print("*************************************")


#-------------------------------------------------------------------------------------------------------------------------------------------------------


def limpiar_reglas():
    # Implementar la función para limpiar todas las reglas del firewall

    print("Limpiando todas las reglas del firewall...")
    comandos = [
        #eliminamos todas las reglas de trafico de red
        [f"sudo iptables -F"],
        #eliminamos cadenas personalizadas que se hayan podido crear
        [f"sudo iptables -X"],
        #y lo mismo pero para las tablas nat
        [f"sudo iptables -t nat -F"],
        [f"sudo iptables -t nat -X"],
    ]
    for comando in comandos:
        ejecutar_comando(comando)
    print("Reglas del firewall limpiadas.")


#-------------------------------------------------------------------------------------------------------------------------------------------------------


def optimizar_firewall():
    """Optimiza el orden de las reglas del firewall: primero los bloqueos (DROP), luego los permisos (ACCEPT)."""
    print("Analizando reglas del firewall...")

    # Obtener todas las reglas actuales en formato de lista
    comando1 = ['sudo iptables -S']
    reglas = ejecutar_comando(comando1)
    if not reglas:
        print("Error al obtener las reglas de iptables.")
        return
    limpiar_reglas()
    bloqueos = []
    permisos = []
    
    # Analizar reglas y clasificarlas
    for regla in reglas.split("\n"):
        print(f'{regla}')
        if "-j DROP" in regla:
            bloqueos.append(regla)
        elif "-j ACCEPT" in regla:
            permisos.append(regla)

    print("Optimizando reglas...")

    

    # Aplicar primero los bloqueos
    for regla in bloqueos:
        comando = f"sudo iptables {regla}"
        print(comando)
        ejecutar_comando(comando)

    # Aplicar luego los permisos
    for regla in permisos:
        comando = f"sudo iptables {regla}"
        print(comando)
        ejecutar_comando(comando)



#-------------------------------------------------------------------------------------------------------------------------------------------------------


def configurar_fail2ban():
    print("\033c", end="")
    """Menú interactivo para configurar Fail2Ban."""
    while True:
        print("\n*************************************")
        print("*  Configuración de Fail2Ban (SSH)  *")
        print("*************************************")
        print("1. Configurar Fail2Ban para SSH")
        print("2. Ver configuración actual de Fail2Ban")
        print("3. Desactivar Fail2Ban")
        print("4. Desbanear una IP")
        print("5. Ver IPs bloqueadas")
        print("6. Volver al menú principal")
        print("*************************************")

        opcion_fail2ban = input("Selecciona una opción [1-6]: ")

        if opcion_fail2ban == "1":
            configurar_fail2ban_ssh()
        elif opcion_fail2ban == "2":
            ver_configuracion_fail2ban()
        elif opcion_fail2ban == "3":
            desactivar_fail2ban()
        elif opcion_fail2ban == "4":
            ip = input("Introduce la IP a desbloquear: ")
            comando = f"sudo fail2ban-client set sshd unbanip {ip}"
            ejecutar_comando(comando)
            print(f"IP {ip} desbaneada.")
        elif opcion_fail2ban == "5":
            comando = "sudo fail2ban-client status sshd"
            ejecutar_comando(comando)
        elif opcion_fail2ban == "6":
            break
        else:
            print("Opción inválida. Intenta de nuevo.")

        input("Presiona Enter para continuar...")


#-------------------------------------------------------------------------------------------------------------------------------------------------------

def configurar_fail2ban_ssh():
    print("\033c", end="")

    """Configura Fail2Ban para proteger SSH."""
    print("****************************************")
    print("*  Configuración de Fail2Ban para SSH  *")
    print("****************************************")

    # Pedir al usuario las configuraciones personalizadas
    bantime = input("Introduce el tiempo de bloqueo (bantime) en segundos (Ej: 600): ")
    findtime = input("Introduce el tiempo en el que se cuentan los intentos fallidos (findtime) en segundos (Ej: 600): ")
    maxretry = input("Introduce el número máximo de intentos fallidos (maxretry) antes de bloquear la IP (Ej: 3): ")
    incrementa_bantime = input("¿Quieres que el tiempo de bloqueo aumente progresivamente? (si/no): ").lower()

    if incrementa_bantime == "si":
        incremento = input("Introduce el incremento del tiempo de bloqueo en segundos (Ej: 300): ")
        bantime_increment = f"bantime.increment = {incremento}\n"
    else:
        bantime_increment = ""

    # Guardar la configuración personalizada en el archivo jail.local
    jail_local_content = f"""
[DEFAULT]
bantime  = {bantime}
findtime = {findtime}
maxretry = {maxretry}
{bantime_increment}

[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = {maxretry}
"""
    
    # Escribir la configuración en el archivo
    try:
        with open("/etc/fail2ban/jail.local", "w") as archivo:
            archivo.write(jail_local_content)
    except PermissionError:
        print("Error: No tienes permisos para escribir en /etc/fail2ban/jail.local. Necesitas privilegios de superusuario.")
        return

    # Reiniciar Fail2Ban para aplicar la configuración
    print("Aplicando configuración...")
    ejecutar_comando("sudo systemctl restart fail2ban")


#-------------------------------------------------------------------------------------------------------------------------------------------------------


def ver_configuracion_fail2ban():
    print("\033c", end="")

    """Muestra la configuración actual de Fail2Ban."""
    print("**************************************")
    print("*  Configuración Actual de Fail2Ban  *")
    print("**************************************")
    
    # Mostrar el contenido del archivo jail.local
    try:
        with open("/etc/fail2ban/jail.local", "r") as archivo:
            print(archivo.read())
    except FileNotFoundError:
        print("No se encontró el archivo de configuración jail.local. ¿Está Fail2Ban instalado?")
    
    # Mostrar el estado actual de Fail2Ban
    print("**************************************")
    ejecutar_comando("sudo fail2ban-client status")
    print("**************************************")


#-------------------------------------------------------------------------------------------------------------------------------------------------------

def desactivar_fail2ban():
    print("\033c", end="")

    """Detiene y desactiva Fail2Ban."""
    print("***************************")
    print("*  Desactivando Fail2Ban  *")
    print("***************************")
    
    # Detener y deshabilitar el servicio Fail2Ban
    ejecutar_comando("sudo systemctl stop fail2ban")
    ejecutar_comando("sudo systemctl disable fail2ban")
    
    print("Fail2Ban ha sido desactivado.")



#-------------------------------------------------------------------------------------------------------------------------------------------------------


def mitigar_ddos():
    print("\033c", end="")

    print("Configuración interactiva para mitigación de DDoS")
    print("-----------------------------------------------")



    # 1. Limitar conexiones por IP
    limit_ip = input("¿Deseas limitar el número de conexiones simultáneas por IP? (s/n): ")
    if limit_ip.lower() == "s":
        max_conexiones = input("Introduce el número máximo de conexiones simultáneas por IP (ej. 10): ")
        comando = f"iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above {max_conexiones} --connlimit-mask 32 -j DROP"
        ejecutar_comando(comando)
        print(f"Se ha configurado un límite de {max_conexiones} conexiones por IP.")



    # 2. Limitar tasa global de paquetes SYN
    limit_syn = input("¿Deseas limitar la tasa de paquetes SYN global? (s/n): ")
    if limit_syn.lower() == "s":
        syn_rate = input("Introduce la tasa máxima de paquetes SYN por segundo (ej. 50): ")
        syn_burst = input("Introduce el burst inicial permitido (ej. 100): ")
        comando1 = f"iptables -A INPUT -p tcp --syn -m limit --limit {syn_rate}/second --limit-burst {syn_burst} -j ACCEPT"
        comando2 = "iptables -A INPUT -p tcp --syn -j DROP"
        ejecutar_comando(comando1)
        ejecutar_comando(comando2)
        print(f"Se ha configurado una tasa de {syn_rate} paquetes SYN/segundo con un burst inicial de {syn_burst}.")



    # 3. Limitar conexiones HTTP
    limit_http = input("¿Deseas limitar el número de conexiones HTTP por IP? (s/n): ")
    if limit_http.lower() == "s":
        max_http = input("Introduce el número máximo de conexiones HTTP por IP (ej. 20): ")
        comando = f"iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above {max_http} --connlimit-mask 32 -j DROP"
        ejecutar_comando(comando)
        print(f"Se ha configurado un límite de {max_http} conexiones HTTP por IP.")



    # 4. Bloquear paquetes inválidos
    block_invalid = input("¿Deseas bloquear paquetes inválidos? (s/n): ")
    if block_invalid.lower() == "s":
        comando = "iptables -A INPUT -m conntrack --ctstate INVALID -j DROP"
        ejecutar_comando(comando)
        print("Se han bloqueado paquetes inválidos.")



    # 5. Limitar tráfico UDP
    limit_udp = input("¿Deseas limitar la tasa de tráfico UDP? (s/n): ")
    if limit_udp.lower() == "s":
        udp_rate = input("Introduce la tasa máxima de paquetes UDP por segundo (ej. 10): ")
        udp_burst = input("Introduce el burst inicial permitido para UDP (ej. 20): ")
        comando1 = f"iptables -A INPUT -p udp -m limit --limit {udp_rate}/second --limit-burst {udp_burst} -j ACCEPT"
        comando2 = "iptables -A INPUT -p udp -j DROP"
        ejecutar_comando(comando1)
        ejecutar_comando(comando2)
        print(f"Se ha configurado una tasa de {udp_rate} paquetes UDP/segundo con un burst inicial de {udp_burst}.")



    # 6. Protección contra ping flood
    limit_icmp = input("¿Deseas proteger contra ping flood (ICMP)? (s/n): ")
    if limit_icmp.lower() == "s":
        icmp_rate = input("Introduce la tasa máxima de solicitudes de eco (ping) por segundo (ej. 10): ")
        icmp_burst = input("Introduce el burst inicial permitido para ICMP (ej. 20): ")
        comando1 = f"iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit {icmp_rate}/second --limit-burst {icmp_burst} -j ACCEPT"
        comando2 = "iptables -A INPUT -p icmp -j DROP"
        ejecutar_comando(comando1)
        ejecutar_comando(comando2)
        print(f"Se ha configurado una tasa de {icmp_rate} pings/segundo con un burst inicial de {icmp_burst}.")

    print("Configuración de mitigación de DDoS completada. Verifica con 'iptables -L -n -v'.")
    input("Presiona Enter para continuar...")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

def escaneo_puertos():
    print('Escaneando puertos abiertos...')
    comando = "netstat -tuln"
    salida = ejecutar_comando(comando)
    print(salida)
    input('\nPresiona Enter para continuar...')
    
#-------------------------------------------------------------------------------------------------------------------------------------------------------

def monitoreo_trafico():
    # Implementar el monitoreo de tráfico en tiempo real
    print('monitoreando trafico en tiempo real...')
    subprocess.call("sudo iftop", shell=True)


#-------------------------------------------------------------------------------------------------------------------------------------------------------

def analizar_logs():
    """Selecciona entre análisis simple o avanzado de logs."""
    print("\033c", end="")
    print("1. Análisis Simple de Logs")
    print("2. Análisis Avanzado de Logs")
    print("3. Volver")
    
    # Solicitar la opción al usuario
    opcion_logs = input("Selecciona una opción [1-2]: ")
    
    if opcion_logs == '1':
        analizar_logs_simple()  # Llama a la función de análisis simple
    elif opcion_logs == '2':
        analizar_logs_avanzado()  # Llama a la función de análisis avanzado
    elif opcion_logs == '3':
        return
    else:
        print("Opción inválida.")
        input('\nPresiona Enter para continuar...')
        analizar_logs()


#-------------------------------------------------------------------------------------------------------------------------------------------------------

def analizar_logs_simple():
    """Realiza un análisis simple de logs del sistema, mostrando los últimos registros."""
    
    print("\033c", end="")  # Limpiar la pantalla (equivalente a 'clear' en Bash)
    print("*****************************")
    print("* Análisis de Logs - Simple *")
    print("*****************************")
    print("Logs más importantes:")

    # Verificar los logs más importantes
    print("\n--- Últimos registros de autenticación (auth.log) ---")
    salida = ejecutar_comando("sudo tail -n 20 /var/log/auth.log")
    print(salida)
    
    print("\n--- Últimos registros del sistema (syslog) ---")
    salida = ejecutar_comando("sudo tail -n 20 /var/log/syslog")
    print(salida)
    print("\n--- Últimos registros de errores del kernel (dmesg) ---")
    salida = ejecutar_comando("sudo dmesg | tail -n 20")
    print(salida)
    print("\n--- Últimos registros de Fail2Ban ---")
    salida = ejecutar_comando("sudo tail -n 20 /var/log/fail2ban.log")
    print(salida)
    print("****************************")
    print("Análisis completado (resumen).")
    print("****************************")
    input('\nPresiona Enter para continuar...')


#-------------------------------------------------------------------------------------------------------------------------------------------------------

def analizar_logs_avanzado():
    """Realiza un análisis avanzado de logs del sistema."""
    
    print("\033c", end="")  # Limpiar la pantalla (equivalente a 'clear' en Bash)
    print("*******************************")
    print("* Análisis de Logs - Avanzado *")
    print("*******************************")
    print("Mostrando todos los logs disponibles en el sistema...\n")

    # Mostrar los logs del sistema
    print("--- Logs de autenticación (auth.log) ---")
    salida = ejecutar_comando("sudo cat /var/log/auth.log")
    print(salida)
    print("\n--- Logs del sistema (syslog) ---")
    salida = ejecutar_comando("sudo cat /var/log/syslog")
    print(salida)
    print("\n--- Logs del kernel (dmesg) ---")
    salida = ejecutar_comando("sudo dmesg")
    print(salida)
    print("\n--- Logs de Fail2Ban ---")
    salida = ejecutar_comando("sudo cat /var/log/fail2ban.log")
    print(salida)
    print("\n--- Logs de Apache (si se utiliza) ---")
    salida = ejecutar_comando("sudo cat /var/log/apache2/access.log")
    print(salida)
    salida = ejecutar_comando("sudo cat /var/log/apache2/error.log")
    print(salida)
    print("\n--- Logs de Nginx (si se utiliza) ---")
    salida = ejecutar_comando("sudo cat /var/log/nginx/access.log")
    print(salida)
    salida = ejecutar_comando("sudo cat /var/log/nginx/error.log")
    print(salida)
    
    print("******************************")
    print("Análisis completado (avanzado).")
    print("******************************")
    input('\nPresiona Enter para continuar...')


#-------------------------------------------------------------------------------------------------------------------------------------------------------

def escaneo_red_local():
    # Implementar el escaneo de la red local
    salida = ejecutar_comando("ip -o -f inet addr show | awk '/scope global/ {print $4}'")
    if not salida:
        print('no se pudo detectar la direccion automaticamente')
        salida = input('Introduce la direccion de red: ')
    subprocess.call(f"netdiscover -r {salida}", shell=True)
   

#-------------------------------------------------------------------------------------------------------------------------------------------------------

def escaneo_red_externa():
    print("******************************")
    print("* Escaneo de una Red Externa *")
    print("******************************")
    red_externa = input("Introduce la dirección IP o rango a escanear (Ej: 192.168.1.0/24 o 192.168.1.100-200): ")
    print(f"Escaneando la red externa: {red_externa}")
    salida = ejecutar_comando(f"nmap -sn {red_externa}")
    print(salida)
    input('\nPresiona Enter para continuar...')
#-------------------------------------------------------------------------------------------------------------------------------------------------------


def generar_reporte():
    """Genera un reporte de seguridad con información del firewall, Fail2Ban, logs y uso del sistema."""
    
    print("Generando reporte de seguridad...")
    nombre_reporte = "reporte_seguridad.txt"
    
    # Limpiar pantalla (opcional)
    os.system("clear")

    # Escribir encabezado con la fecha
    with open(nombre_reporte, "w") as f:
        f.write(f"Fecha: {ejecutar_comando('date')}\n")
        f.write("----------------------------\n")
        f.write("Estado de las reglas actuales del firewall:\n")
        f.write(f"{ejecutar_comando('sudo iptables -L')}\n")
        f.write("----------------------------\n")
        f.write("Estado de Fail2Ban:\n")
        f.write(f"{ejecutar_comando('sudo fail2ban-client status sshd')}\n")
        f.write("----------------------------\n")
        f.write("Últimos logs de SSH:\n")
        f.write(f"{ejecutar_comando('sudo tail -n 100 /var/log/auth.log')}\n")
        f.write("----------------------------\n")
        f.write("Últimos logs del sistema:\n")
        f.write(f"{ejecutar_comando('sudo tail -n 100 /var/log/syslog')}\n")
        f.write("----------------------------\n")
        f.write("Uso de Disco:\n")
        f.write(f"{ejecutar_comando('df -h')}\n")
        f.write("----------------------------\n")
        f.write("Uso de Memoria:\n")
        f.write(f"{ejecutar_comando('free -h')}\n")
    
    print(f"Reporte generado: {nombre_reporte}")
    input('\nPresiona Enter para continuar...')
#-------------------------------------------------------------------------------------------------------------------------------------------------------


def escanear_vulnerabilidades():
    """Realiza un escaneo de vulnerabilidades del sistema usando Lynis."""
    
    print("\033c", end="")  # Equivalente a 'clear' en Bash para limpiar la pantalla
    print("*******************************************")
    print("* Escaneo de Vulnerabilidades del Sistema *")
    print("*******************************************\n")
    print("Puede tardar unos minutos...\n")

    # Ejecutar Lynis y guardar el reporte
    reporte = "lynis_report.txt"
    ejecutar_comando(f"sudo lynis audit system > {reporte}")

    print("Escaneo completado. El informe se ha guardado en lynis_report.txt.")
    print("*****************************")
    print("El informe de vulnerabilidades puede ser revisado en el archivo 'lynis_report.txt'.")


#-------------------------------------------------------------------------------------------------------------------------------------------------------
def listar_reglas(cadena):
    """Muestra las reglas numeradas de una cadena específica."""
    print(f"--- Reglas en la cadena {cadena} ---")
    return ejecutar_comando(f"sudo iptables -L {cadena} --line-numbers -n")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

def eliminar_reglas2(cadena, reglas):
    """Elimina múltiples reglas especificadas en una cadena."""
    for regla_num in reglas:
        print(f"Eliminando la regla número {regla_num} de la cadena {cadena}...")
        resultado = ejecutar_comando(f"sudo iptables -D {cadena} {regla_num}")
        print(f"Se ha eliminado la regla número {regla_num} en la cadena {cadena}.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

def eliminar_reglas():
    """Función principal para eliminar reglas del firewall."""
    print("************************************")
    print("*   Eliminar Reglas del Firewall   *")
    print("************************************")

    while True:
        # Mostrar las reglas de todas las cadenas
        resultado = ejecutar_comando("sudo iptables -L --line-numbers -n")
        print(resultado)

        # Preguntar al usuario qué tipo de cadena desea modificar
        opcion = input("¿Quieres eliminar reglas de INPUT (1), FORWARD (2), OUTPUT (3) o salir (4)? [1-4]: ")
        
        if opcion not in ["1", "2", "3"]:
            if opcion == "4":
                print("Saliendo del menú de eliminación de reglas.")
                break
            else:
                print("Opción no válida. Elige 1, 2, 3 o 4.")
                continue
        
        # Definir la cadena según la opción
        if opcion == "1":
            cadena = "INPUT"
        elif opcion == "2":
            cadena = "FORWARD"
        else:
            cadena = "OUTPUT"

        # Listar las reglas de la cadena seleccionada
        listar_reglas(cadena)

        # Solicitar al usuario los números de regla a eliminar (separados por comas)
        reglas_str = input("Introduce los números de las reglas a eliminar (separados por comas de mayor a menor: 4,3,1): ")

        # Convertir la cadena de números a una lista de enteros
        reglas = [int(x.strip()) for x in reglas_str.split(",") if x.strip().isdigit()]

        # Validar si hay reglas válidas
        if not reglas:
            print("No se ha ingresado ningún número de regla válido.")
            continue

        # Confirmar la eliminación
        confirmacion = input(f"¿Seguro que deseas eliminar las reglas {', '.join(map(str, reglas))} de la cadena {cadena}? (s/n): ")
        if confirmacion.lower() == 's':
            eliminar_reglas2(cadena, reglas)

        # Preguntar si desea eliminar más reglas
        continuar = input("¿Quieres eliminar más reglas? (s/n): ")
        if continuar.lower() != "s":
            print("Saliendo del menú de eliminación de reglas.")
            break

    # Guardar las reglas de iptables para que se mantengan después del reinicio
    ejecutar_comando("sudo netfilter-persistent save")
    print("Se han guardado las reglas de iptables para que sean persistentes.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Menú principal
def mostrar_menu():
    while True:
        os.system('clear')
        print("**********************************")
        print("*  Gestión Avanzada de Seguridad *")
        print("**********************************")
        print("1. Configurar Firewall")
        print("2. Configuración de Fail2Ban (SSH)")
        print("3. Limitar Conexiones por IP (Prevención DDoS)")
        print("4. Escaneo de Puertos Abiertos")
        print("5. Monitoreo de Tráfico en Tiempo Real")
        print("6. Análisis de Logs (SSH y Sistema)")
        print("7. Escaneo de la Red Local")
        print("8. Escaneo de una Red Externa")
        print("9. Generar Reporte de Seguridad")
        print("10. Hacer un escaneo de vulnerabilidades")
        print("11. Eliminar reglas del firewall")
        print("12. Salir")
        print("******************************")
        opcion = input("Selecciona una opción [1-12]: ")
        if opcion == '1':
            configurar_firewall()
        elif opcion == '2':
            configurar_fail2ban()
        elif opcion == '3':
            mitigar_ddos()
        elif opcion == '4':
            escaneo_puertos()
        elif opcion == '5':
            monitoreo_trafico()
        elif opcion == '6':
            analizar_logs()
        elif opcion == '7':
            escaneo_red_local()
        elif opcion == '8':
            escaneo_red_externa()
        elif opcion == '9':
            generar_reporte()
        elif opcion == '10':
            escanear_vulnerabilidades()
        elif opcion == '11':
            eliminar_reglas()
        elif opcion == '12':
            ejecutar_comando("sudo netfilter-persistent save")
            exit(0)
        else:
            print("Opción inválida. Intenta de nuevo.")


if __name__ == "__main__":
    mostrar_menu()
