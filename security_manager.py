#!/home/umbra/security_manager/.venv/bin/python3
import os
import subprocess
import re
#para comprobar si una ip es valida o no
import ipaddress
import shlex
import inquirer  # Importar la librería inquirer
import logging
from typing import List
import colorama
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from colorama import Fore, Back, Style, init


def ejecutar_comando(comando):
   
    try:
        resultado = subprocess.run(comando, shell=True, text=True, capture_output=True)
        if resultado.returncode == 0:
            return resultado.stdout.strip()
    except Exception as e:
        print(f"Error ejecutando el comando: {e}")
        return None
    
#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Comprobar si el script se está ejecutando como root
#if os.geteuid() != 0:
 #   print("Este script debe ejecutarse como root o con sudo .")
  #  exit(1)


#-------------------------------------------------------------------------------------------------------------------------------------------------------

def ip_bloqueada(ip):
    """Verifica si una IP está bloqueada en iptables."""
    comando = f"  iptables -C INPUT -s {ip} -j DROP"
    return ejecutar_comando(comando) is not None

#-------------------------------------------------------------------------------------------------------------------------------------------------------

def ip_permitida(ip):
    """Verifica si una IP está permitida en iptables."""
    comando = f"  iptables -C INPUT -s {ip} -j ACCEPT"
    return ejecutar_comando(comando) is not None

    
#-------------------------------------------------------------------------------------------------------------------------------------------------------
def regla_existente_puerto(cadena, protocolo, puerto, direccion):
    #Verifica si una regla ya existe en iptables utilizando una búsqueda precisa.
    reglas = ejecutar_comando("  iptables-save")
    if reglas:
        # Ajustamos el patrón para que coincida con la salida exacta de iptables-save
        #sport y dport son el source y el destination
        if direccion == "dport":
            patron = rf"-A {cadena} -p {protocolo} -m {protocolo} --dport {puerto} -j ACCEPT"
        else:  # Para sport
            patron = rf"-A {cadena} -p {protocolo} -m {protocolo} --sport {puerto} -j ACCEPT"
        #upper porque en el comando de iptables tambien es mayusculas y se ve mas visual
        if re.search(patron, reglas):
            print(f"[v] Regla encontrada para {protocolo.upper()} en {direccion.upper()} {puerto}.")
            return True
        else:
            print(f"[x] No se encontró la regla exacta con el patrón: {patron}")
    return False
#-------------------------------------------------------------------------------------------------------------------------------------------------------

    
def validar_puerto(puerto):
    #comprobamos si nos han pasado un solo puerto o un rango entero
    if ':' in puerto:
        #si es un rango, lo separamos en dos partes, separadas por los ':'
        partes = puerto.split(':')
        if len(partes) == 2 and all(p.isdigit() for p in partes):
            #las convertimos a entero
            inicio, fin = map(int, partes)
            #vemos si esta en un rango posible para los puertos
            return 1 <= inicio <= 65535 and 1 <= fin <= 65535
        return False
    return puerto.isdigit() and 1 <= int(puerto) <= 65535
#-------------------------------------------------------------------------------------------------------------------------------------------------------
#funcion para cuando necesitamos una respuesta de si o no.
def confirmar_accion(mensaje):
    return input(f"{mensaje} (s/n): ").lower() == 's'
#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Funciones para gestionar reglas de puertos
def permitir_puerto():
    #aqui necesitamos saber 3 cosas, el puerto o rango de puertos, el protocolo, y el sentido del trafico
    puerto = input("Introduce el número de puerto o rango de puertos a permitir (Ej: 8080 o 8000:8080): ")
    if not validar_puerto(puerto):
        print("Puerto o rango de puertos inválido.")
        return
    tipo = input("¿Deseas permitir tráfico TCP, UDP o ambos? (tcp/udp/ambos): ").lower()
    direccion = input("¿Deseas permitir tráfico entrante, saliente o ambos? (entrante/saliente/ambos): ").lower()

    
    #me gusta mas esta manera de hacerlo, me parece mas elegante que la de abajo
    tipos = {"tcp": ["tcp"], "udp": ["udp"], "ambos": ["tcp", "udp"]}.get(tipo, [])
    direcciones = {"entrante": ["dport"], "saliente": ["sport"], "ambos": ["dport", "sport"]}.get(direccion, [])
    
    if not tipos or not direcciones:
        print("Opción no válida para tipo de tráfico o dirección.")
        return

    #comprobamos si el usuario realmente  quiere realizar la accion
    if not confirmar_accion("¿Estás seguro de que quieres aplicar estos cambios?"):
        print("Operación cancelada.")
        return

    #iteramos sobre tipos
    for tipo in tipos:
        #iteramos sobre direcciones
        for dir_flag in direcciones:
            #si es entrante, es INPUT, de lo contrario es OUTPUT
            cadena = "INPUT" if dir_flag == "dport" else "OUTPUT"

            # Verificar si existe una regla de bloqueo para este puerto
            if regla_existente_drop_puerto(cadena, tipo, puerto, dir_flag):
                print(f"Se encontró una regla de bloqueo para {tipo} en el puerto {puerto} ({direccion}). Eliminando...")
                try:
                    comando_eliminar = f"  iptables -D {cadena} -p {tipo} --{dir_flag} {puerto} -j DROP"
                    ejecutar_comando(comando_eliminar)
                except Exception as e:
                    print(f"Error al eliminar la regla de bloqueo: {e}")

                
            if regla_existente_puerto(cadena, tipo, puerto, dir_flag):
                print(f"La regla para {tipo} en el puerto {puerto} ({direccion}) ya existe.")
            else:
                try:
                    comando = f"  iptables -I {cadena} 1 -p {tipo} --{dir_flag} {puerto} -j ACCEPT"
                    ejecutar_comando(comando)
                    print(f"Regla agregada: {tipo.upper()} {direccion.upper()} en el puerto {puerto}")
                except Exception as e:
                    print(f"Error al agregar la regla: {e}")
    
    print('Operacion completada')
        
#-------------------------------------------------------------------------------------------------------------------------------------------------------         
def regla_existente_drop_puerto(cadena, protocolo, puerto, direccion):
    """Verifica si una regla de bloqueo ya existe en iptables."""
    #con iptables-save, obtenemos las reglas de itables de forma mas operable
    reglas = ejecutar_comando("iptables-save")
    if reglas:
        #definimos el patron para dport y sport
        if direccion == "dport":
            patron = rf"-A {cadena} -p {protocolo} -m {protocolo} --dport {puerto} -j DROP"
        else:  # Para sport
            patron = rf"-A {cadena} -p {protocolo} -m {protocolo} --sport {puerto} -j DROP"
        #y si el patron se encuetra  pues decimos que se ha encontrado una regla
        if re.search(patron, reglas):
            print(f"[v] Regla de bloqueo encontrada para {protocolo.upper()} en {direccion.upper()} {puerto}.")
            return True
        else:
            print(f"[x] No se encontró la regla de bloqueo exacta con el patrón: {patron}")
    return False

#-------------------------------------------------------------------------------------------------------------------------------------------------------
#este es igual que el de permitir puerto
def cerrar_puerto():
    puerto = input("Introduce el número de puerto o rango de puertos a cerrar (Ej: 8080 o 8000:8080): ")
    if not validar_puerto(puerto):
        print("Puerto o rango de puertos inválido.")
        return

    tipo = input("¿Deseas cerrar tráfico TCP, UDP o ambos? (tcp/udp/ambos): ").lower()
    direccion = input("¿Deseas cerrar tráfico entrante, saliente o ambos? (entrante/saliente/ambos): ").lower()

    tipos = {"tcp": ["tcp"], "udp": ["udp"], "ambos": ["tcp", "udp"]}.get(tipo, [])
    direcciones = {"entrante": ["dport"], "saliente": ["sport"], "ambos": ["dport", "sport"]}.get(direccion, [])

    if not tipos or not direcciones:
        print("Opción no válida para tipo de tráfico o dirección.")
        return

    if not confirmar_accion("¿Estás seguro de que quieres aplicar estos cambios?"):
        print("Operación cancelada.")
        return

    for tipo in tipos:
        for dir_flag in direcciones:
            cadena = "INPUT" if dir_flag == "dport" else "OUTPUT"
            if regla_existente_puerto(cadena, tipo, puerto, dir_flag):
                comando = f"  iptables -D {cadena} -p {tipo} --{dir_flag} {puerto} -j ACCEPT"
                try:
                    ejecutar_comando(comando)
                    print(f"Regla eliminada: {tipo.upper()} {direccion.upper()} en el puerto {puerto}")
                except Exception as e:
                    print(f"Error al eliminar la regla: {e}")
            else:
                print(f"No existe una regla para {tipo} en el puerto {puerto} ({direccion}).")
                if confirmar_accion("¿Quieres añadir una regla de bloqueo?"):
                    comando = f"  iptables -I {cadena} -p {tipo} --{dir_flag} {puerto} -j DROP"
                    try:
                        ejecutar_comando(comando)
                        print(f"Regla de bloqueo añadida: {tipo.upper()} {direccion.upper()} en el puerto {puerto}")
                    except Exception as e:
                        print(f"Error al añadir la regla de bloqueo: {e}")

    print("Operación completada.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------
def validar_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    
#lo malo es que este tambien se traga las ips sueltas
def validar_rango_ip(rango):
    try:
        ipaddress.ip_network(rango, strict=False)  # strict=False permite hosts bits
        return True
    except ValueError:
        return False


#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Funciones para gestionar reglas de IP
def bloquear_ip():
    """Bloquea completamente una IP en iptables, incluyendo ping."""
    #pillamos la ip sin espacios, con la funcion strip()
    ip = input("Introduce la IP a bloquear: ").strip()
    
    if not validar_ip(ip):
        print('Ip no valida')
        return


    # Eliminar reglas de aceptación para evitar conflictos
    #si la ip esta permitida, ejecutamos todos los comandos de la lista para tratar de eliminar todas las reglas posibles
    if ip_permitida(ip):
        print(f"Eliminando reglas de aceptación existentes para la IP {ip}...")
        comandos_eliminar = [
            f"  iptables -D INPUT -s {ip} -j ACCEPT",
            f"  iptables -D OUTPUT -d {ip} -j ACCEPT",
            f"  iptables -D FORWARD -s {ip} -j ACCEPT",
            f"  iptables -D FORWARD -d {ip} -j ACCEPT",
            f"  iptables -D INPUT -p icmp --src {ip} -j ACCEPT",
            f"  iptables -D OUTPUT -p icmp --dst {ip} -j ACCEPT",
        ]
        for comando in comandos_eliminar:
            ejecutar_comando(comando)

    # Validar si la IP ya está bloqueada
    if ip_bloqueada(ip):
        print(f"La IP {ip} ya ha sido bloqueada")
        return

    # Bloquear el tráfico de la IP en todas las cadenas (INPUT, OUTPUT, FORWARD)
    if confirmar_accion("Quiere agregar relgas de denegacion, o le vale con eliminar las de aceptacion?"):
        comandos_bloqueo = [
            f"  iptables -I INPUT 1 -s {ip} -j DROP",
            f"  iptables -I OUTPUT 1 -d {ip} -j DROP",
            f"  iptables -I FORWARD 1 -s {ip} -j DROP",
            f"  iptables -I FORWARD 1 -d {ip} -j DROP",
            f"  iptables -I INPUT 1 -p icmp --src {ip} -j DROP",
            f"  iptables -I OUTPUT 1 -p icmp --dst {ip} -j DROP",
        ]
        for comando in comandos_bloqueo:
            ejecutar_comando(comando)

    print(f"La IP {ip} ha sido completamente bloqueada (incluido ping).")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#El funcionamiento es el mismo que para bloquear una ip
def permitir_ip():
    """Permitir tráfico de una IP específica (comprobando si está bloqueada)"""
    ip = input("Introduce la IP a permitir: ").strip()
    #vemos si la ip es valida
    if not validar_ip(ip):
        print('Ip no valida')
        return
    
    if ip_bloqueada(ip):
         
        if confirmar_accion(f"¡Advertencia! La IP {ip} está bloqueada. ¿Quieres eliminar las reglas de bloqueo y permitirla?"):
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
        [f"  iptables -I INPUT 1 -s {ip} -j ACCEPT"],
        [f"  iptables -I OUTPUT 1 -d {ip} -j ACCEPT"],
        [f"  iptables -I FORWARD 1 -s {ip} -j ACCEPT"],
        [f"  iptables -I FORWARD 1 -d {ip} -j ACCEPT"],
        [f"  iptables -I INPUT 1 -p icmp --src {ip} -j ACCEPT"],
        [f"  iptables -I OUTPUT 1 -p icmp --dst {ip} -j ACCEPT"],

    ]
    for comando in comandos_ACCEPT:
        ejecutar_comando(comando)

    print(f"La IP {ip} ha sido completamente permitida (incluido ping).")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Funcion para permitir un rango de ips que es muy parecida a las de las ips sueltas
def permitir_rango_ip():
    """Permitir tráfico de un rango de IPs (comprobando si está permitido)"""
    rango = input("Introduce el rango de IPs a permitir (Ej: 192.168.1.0/24): ").strip()

    if not validar_rango_ip(rango):
        print('Rango no valido')
        return

    if ip_bloqueada(rango):
        if confirmar_accion(f"¡Advertencia! El rango de IPs {rango} está bloqueado. ¿Quieres eliminar las reglas de bloqueo y permitirlo?"):
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
        [f"  iptables -I INPUT 1 -s {rango} -j ACCEPT"],
        [f"  iptables -I OUTPUT 1 -d {rango} -j ACCEPT"],
        [f"  iptables -I FORWARD 1 -s {rango} -j ACCEPT"],
        [f"  iptables -I FORWARD 1 -d {rango} -j ACCEPT"],
        [f"  iptables -I INPUT -p icmp --src {rango} -j ACCEPT"],
        [f"  iptables -I OUTPUT -p icmp --dst {rango} -j ACCEPT"],
    ]
    for comando in comandos_ACCEPT:
        ejecutar_comando(comando)

    print(f"El rango de IPs {rango} ha sido completamente permitido.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#esta es igual que la de permitir
def denegar_rango_ip():
    """denegar tráfico de un rango de IPs (comprobando si está permitido)"""
    rango = input("Introduce el rango de IPs a denegar (Ej: 192.168.1.0/24): ").strip()

    if not validar_rango_ip(rango):
        print('Rango no valido')
        return

    if ip_permitida(rango):
        if confirmar_accion(f"¡Advertencia! El rango de IPs {rango} está permidido. ¿Quieres eliminar las reglas de permiso y bloquearlo?"):
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

    if confirmar_accion("Quiere agregar relgas de denegacion, o le vale con eliminar las de aceptacion?"):
        # Bloquear el tráfico de la IP en todas las cadenas (INPUT, OUTPUT, FORWARD)
        comandos_ACCEPT = [
            [f"  iptables -I INPUT 1 -s {rango} -j DROP"],
            [f"  iptables -I OUTPUT 1 -d {rango} -j DROP"],
            [f"  iptables -I FORWARD 1 -s {rango} -j DROP"],
            [f"  iptables -I FORWARD 1 -d {rango} -j DROP"],
            [f"  iptables -I INPUT -p icmp --src {rango} -j DROP"],
            [f"  iptables -I OUTPUT -p icmp --dst {rango} -j DROP"],
        ]
        for comando in comandos_ACCEPT:
            ejecutar_comando(comando)

    print(f"El rango de IPs {rango} ha sido completamente bloqueado.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------


def ver_reglas_firewall():
    # Inicializar colorama 
    init(autoreset=True)
    # Lista de cadenas a verificar
    chains = ['INPUT', 'FORWARD', 'OUTPUT']
    
    # Colores para las diferentes acciones
    colors = {
        'ACCEPT': Fore.GREEN,
        'DROP': Fore.RED,
        'REJECT': Fore.RED,
        'RELATED': Fore.YELLOW,
        'ESTABLISHED': Fore.YELLOW,
        'DNAT': Fore.CYAN,
        'SNAT': Fore.CYAN,
        'MASQUERADE': Fore.CYAN
    }
    
    for chain in chains:
        # Encabezado de la cadena con fondo diferente
        print(f"\n{Back.WHITE}{Fore.BLACK}{Style.BRIGHT} Reglas para la cadena {chain}: {Style.RESET_ALL}")
        
        try:
            # Ejecutar comando para obtener las reglas
            result = subprocess.run(
                f"iptables -L {chain} -v -n",
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Procesar la salida línea por línea
            lines = result.stdout.decode().splitlines()
            
            # Imprimir encabezado de tabla
            if len(lines) > 1:
                header = lines[0]
                print(f"{Fore.BLUE}{Style.BRIGHT}{header}")
                
                # Imprimir reglas con colores según la acción
                for line in lines[2:]:  # Saltar las primeras 2 líneas (encabezado y columnas)
                    colored_line = line
                    
                    # Aplicar colores a las palabras clave
                    for keyword, color in colors.items():
                        if keyword in line:
                            colored_line = colored_line.replace(keyword, f"{color}{keyword}{Style.RESET_ALL}")
                    
                    # Si es DROP o REJECT, resaltar toda la línea
                    if "DROP" in line or "REJECT" in line:
                        print(f"{Fore.RED}{colored_line}")
                    # Si es ACCEPT, ponerla en verde
                    elif "ACCEPT" in line:
                        print(f"{Fore.GREEN}{colored_line}")
                    # Para el resto, mostrar con los colores aplicados a palabras clave
                    else:
                        print(colored_line)
            else:
                print(f"{Fore.YELLOW}No hay reglas definidas para esta cadena.")
                
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}No se pudieron obtener las reglas para la cadena {chain}.")


#-------------------------------------------------------------------------------------------------------------------------------------------------------

#para limpiar las reglas del firewall
def limpiar_reglas(n):
    if n:
        comandos = [
            #eliminamos todas las reglas de trafico de red
            [f"  iptables -F"],
            #eliminamos cadenas personalizadas que se hayan podido crear
            [f"  iptables -X"],
            #y lo mismo pero para las tablas nat
            [f"  iptables -t nat -F"],
            [f"  iptables -t nat -X"],
        ]
        for comando in comandos:
            ejecutar_comando(comando)
        return
    # Implementar la función para limpiar todas las reglas del firewall
    else: 
        if confirmar_accion('[!] Seguro que quieres limpiar todas las reglas del firewall??'):
            print("Limpiando todas las reglas del firewall...")
            comandos = [
                #eliminamos todas las reglas de trafico de red
                [f"  iptables -F"],
                #eliminamos cadenas personalizadas que se hayan podido crear
                [f"  iptables -X"],
                #y lo mismo pero para las tablas nat
                [f"  iptables -t nat -F"],
                [f"  iptables -t nat -X"],
            ]
            for comando in comandos:
                ejecutar_comando(comando)
            print("Reglas del firewall limpiadas.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#para ver las reglas de una cadena especifica
def listar_reglas(cadena):
    """Muestra las reglas numeradas de una cadena específica."""
    print(f"--- Reglas en la cadena {cadena} ---")
    return ejecutar_comando(f"  iptables -L {cadena} --line-numbers -n")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#eliminamos las reglas 
def eliminar_reglas2(cadena, reglas):
    """Elimina múltiples reglas especificadas en una cadena."""
    for regla_num in reglas:
        print(f"Eliminando la regla número {regla_num} de la cadena {cadena}...")
        #si algo falla es que esta linea era asi: resultado = ejecutar_comando[...]
        try:
            ejecutar_comando(f"  iptables -D {cadena} {regla_num}")
            print(f"Se ha eliminado la regla número {regla_num} en la cadena {cadena}.")
        except Exception as e:
            print(f"Error al eliminar la regla: {e}")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#funcion para elegir que reglas eliminar
def eliminar_reglas():
    """Función principal para eliminar reglas del firewall."""
    print("************************************")
    print("*   Eliminar Reglas del Firewall   *")
    print("************************************")

    while True:
        # Mostrar las reglas de todas las cadenas
        resultado = ejecutar_comando("  iptables -L --line-numbers -n")
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

        if confirmar_accion(f"¿Seguro que deseas eliminar las reglas {', '.join(map(str, reglas))} de la cadena {cadena}?"):
            eliminar_reglas2(cadena, reglas)

        # Preguntar si desea eliminar más reglas
        if confirmar_accion("¿Quieres eliminar más reglas?"):
            print("Saliendo del menú de eliminación de reglas.")
            break

    # Guardar las reglas de iptables para que se mantengan después del reinicio
    ejecutar_comando("  netfilter-persistent save")
    print("Se han guardado las reglas de iptables para que sean persistentes.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#Esta funcion tengo que mejorar cosas
def optimizar_firewall():
    print("Analizando reglas del firewall...")

    # Obtener todas las reglas actuales en formato de lista
    comando1 = ['  iptables -S']
    reglas = ejecutar_comando(comando1)
    if not reglas:
        print("Error al obtener las reglas de iptables.")
        return

    limpiar_reglas(True)
    bloqueos = []
    permisos = []
    reglas_unicas = set()  # Usamos un conjunto para eliminar duplicados

    # Analizar reglas y clasificarlas
    for regla in reglas.split("\n"):
        regla = regla.strip()
        if not regla or regla.startswith("#"):
            continue  # Ignorar líneas vacías o comentarios
        
        # Eliminar el número de línea si está presente
        regla = re.sub(r'^\[\d+:\w+\]\s*', '', regla)
        
        if regla not in reglas_unicas:
            reglas_unicas.add(regla)
            if "-j DROP" in regla:
                bloqueos.append(regla)
            elif "-j ACCEPT" in regla:
                permisos.append(regla)

    print("Optimizando reglas...")

    # Aplicar primero los bloqueos
    for regla in bloqueos:
        comando = f"  iptables {regla}"
        ejecutar_comando(comando)

    # Aplicar luego los permisos
    for regla in permisos:
        comando = f"  iptables {regla}"
        ejecutar_comando(comando)

    print("Guardando reglas optimizadas...")
    ejecutar_comando("  netfilter-persistent save")
    print("Optimización del firewall completada.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Funciones del menú principal
def mostrar_menu_principal():
    """Muestra el menú principal utilizando inquirer."""
    preguntas = [
        inquirer.List(
            "opcion",
            message="¿Qué quieres hacer?",
            choices=[
                ("Configuración del Firewall", "configurar_firewall"),
                ("Configuración de Fail2Ban (SSH)", "configurar_fail2ban"),
                ("Limitar Conexiones por IP (Prevención DDoS)", "mitigar_ddos"),
                ("Escaneo de Puertos Abiertos", "escaneo_puertos"),
                ("Monitoreo de Tráfico en Tiempo Real", "monitoreo_trafico"),
                ("Análisis de Logs (SSH y Sistema)", "analizar_logs"),
                ("Escaneo de la Red Local", "escaneo_red_local"),
                ("Escaneo de una Red Externa", "escaneo_red_externa"),
                ("Generar Reporte de Seguridad", "generar_reporte"),
                ("Hacer un escaneo de vulnerabilidades", "escanear_vulnerabilidades"),
                ("Eliminar reglas del firewall", "eliminar_reglas"),
                ("Salir", "salir"),
            ],
        ),
    ]
    respuesta = inquirer.prompt(preguntas)
    return respuesta["opcion"]

#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Menú de configuración del firewall
def mostrar_menu_firewall():
    """Muestra el menú de configuración del firewall."""
    preguntas = [
        inquirer.List(
            "opcion",
            message="¿Qué quieres hacer en el firewall?",
            choices=[
                ("Configuración inicial", "configuracion_inicial"),
                ("Reglas de puertos", "reglas_de_puertos"),
                ("Bloquear tráfico de una IP específica", "bloquear_ip"),
                ("Permitir tráfico de una IP específica", "permitir_ip"),
                ("Permitir tráfico en un rango de IPs", "permitir_rango_ip"),
                ("Bloquear tráfico en un rango de IPs", "denegar_rango_ip"),
                ("Ver reglas actuales del firewall", "ver_reglas_firewall"),
                ("Limpiar todas las reglas del firewall", "limpiar_reglas"),
                ("Eliminar reglas concretas del firewall", "eliminar_reglas"),
                ("Volver al menú principal", "volver"),
            ],
        ),
    ]
    respuesta = inquirer.prompt(preguntas)
    return respuesta["opcion"]

#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Menu de fail2ban
def mostrar_menu_fail2ban():
    """Muestra el menú de configuración de Fail2Ban."""
    preguntas = [
        inquirer.List(
            "opcion",
            message="¿Qué quieres hacer en el fail2ban?",
            choices=[
                ("Configurar Fail2Ban", "configurar_fail2ban_ssh"),
                ("Ver configuracion actual del fail2Ban", "ver_configuracion_fail2ban"),
                ("Desactivar Fail2Ban", "desactivar_fail2ban"),
                ("Desbanear una IP", "desbanear_IP"),
                ("Ver IPs bloqueadas", "VIPB"),
                ("Volver al menú principal", "volver"),
            ],
        ),
    ]
    respuesta = inquirer.prompt(preguntas)
    return respuesta["opcion"]
    
#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Menu de reglas de puertos
def mostrar_menu_reglas_puertos():
    """Muestra el menú de reglas de puertos."""
    preguntas = [
        inquirer.List(
            "opcion",
            message="¿Qué quieres hacer con las reglas de puertos?",
            choices=[
                ("Permitir el tráfico en un puerto o rango de puertos", "permitir_puerto"),
                ("Denegar el tráfico en un puerto o rango de puertos", "cerrar_puerto"),
                ("Volver al menú de configuración del firewall", "volver"),
            ],
        ),
    ]
    respuesta = inquirer.prompt(preguntas)
    return respuesta["opcion"]

#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Funciones placeholder para las opciones del menú principal
def configurar_fail2ban_ssh():
    os.system('clear')

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
    ejecutar_comando("  systemctl restart fail2ban")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#simplemente paramos el servicio
def desactivar_fail2ban():
    os.system('clear')

    """Detiene y desactiva Fail2Ban."""
    print("***************************")
    print("*  Desactivando Fail2Ban  *")
    print("***************************")
    
    # Detener y deshabilitar el servicio Fail2Ban
    ejecutar_comando("  systemctl stop fail2ban")
    ejecutar_comando("  systemctl disable fail2ban")
    
    print("Fail2Ban ha sido desactivado.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#desbaneamos una ip de fail2ban
def desbanear_IP():
    ip = input("Introduce la IP a desbloquear: ")
    comando = f"  fail2ban-client set sshd unbanip {ip}"
    ejecutar_comando(comando)
    print(f"IP {ip} desbaneada.")
  
# ---------------------------------------------------------------------------------------------------------------------------

#ver ips bloqueadas en fail2ban
def VIPB():
    comando = "  fail2ban-client status sshd"
    ejecutar_comando(comando)

#-------------------------------------------------------------------------------------------------------------------------------------------------------

### estudiar en casa
def mitigar_ddos():
    os.system('clear')

    print("Configuración interactiva para mitigación de DDoS")
    print("-----------------------------------------------")



    # 1. Limitar conexiones por IP
    if confirmar_accion("¿Deseas limitar el número de conexiones simultáneas por IP?"):
        max_conexiones = input("Introduce el número máximo de conexiones simultáneas por IP (ej. 10): ")
        comando = f"iptables -A INPUT -p tcp --syn -m connlimit --connlimit-above {max_conexiones} --connlimit-mask 32 -j DROP"
        ejecutar_comando(comando)
        print(f"Se ha configurado un límite de {max_conexiones} conexiones por IP.")



    # 2. Limitar tasa global de paquetes SYN
    if confirmar_accion("¿Deseas limitar la tasa de paquetes SYN global?"):
        syn_rate = input("Introduce la tasa máxima de paquetes SYN por segundo (ej. 50): ")
        syn_burst = input("Introduce el burst inicial permitido (ej. 100): ")
        comando1 = f"iptables -A INPUT -p tcp --syn -m limit --limit {syn_rate}/second --limit-burst {syn_burst} -j ACCEPT"
        comando2 = "iptables -A INPUT -p tcp --syn -j DROP"
        ejecutar_comando(comando1)
        ejecutar_comando(comando2)
        print(f"Se ha configurado una tasa de {syn_rate} paquetes SYN/segundo con un burst inicial de {syn_burst}.")



    # 3. Limitar conexiones HTTP
    if confirmar_accion("¿Deseas limitar el número de conexiones HTTP por IP?"):
        max_http = input("Introduce el número máximo de conexiones HTTP por IP (ej. 20): ")
        comando = f"iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above {max_http} --connlimit-mask 32 -j DROP"
        ejecutar_comando(comando)
        print(f"Se ha configurado un límite de {max_http} conexiones HTTP por IP.")



    # 4. Bloquear paquetes inválidos
    if confirmar_accion("¿Deseas bloquear paquetes inválidos?"):
        comando = "iptables -A INPUT -m conntrack --ctstate INVALID -j DROP"
        ejecutar_comando(comando)
        print("Se han bloqueado paquetes inválidos.")



    # 5. Limitar tráfico UDP
    if confirmar_accion("¿Deseas limitar la tasa de tráfico UDP?"):
        udp_rate = input("Introduce la tasa máxima de paquetes UDP por segundo (ej. 10): ")
        udp_burst = input("Introduce el burst inicial permitido para UDP (ej. 20): ")
        comando1 = f"iptables -A INPUT -p udp -m limit --limit {udp_rate}/second --limit-burst {udp_burst} -j ACCEPT"
        comando2 = "iptables -A INPUT -p udp -j DROP"
        ejecutar_comando(comando1)
        ejecutar_comando(comando2)
        print(f"Se ha configurado una tasa de {udp_rate} paquetes UDP/segundo con un burst inicial de {udp_burst}.")



    # 6. Protección contra ping flood
    if confirmar_accion("¿Deseas proteger contra ping flood (ICMP)?"):
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

#un simple netstat para ver los puertos usados, que no los permitidos en el firewall
def escaneo_puertos():
    print('Escaneando puertos abiertos...')
    comando = "netstat -tuln"
    salida = ejecutar_comando(comando)
    print(salida)
    input('\nPresiona Enter para continuar...')
    
#-------------------------------------------------------------------------------------------------------------------------------------------------------

#simplemente iftop
def monitoreo_trafico():
    # Implementar el monitoreo de tráfico en tiempo real
    print('monitoreando trafico en tiempo real...')
    subprocess.call("  iftop", shell=True)

#-------------------------------------------------------------------------------------------------------------------------------------------------------
#crear la clase Log analyzer
class LogAnalyzer:
    def __init__(self):
        # Configuración de colores
        colorama.init()
        self.console = Console()

    def comando_log(self, comando: str) -> str:
        """Ejecuta un comando del sistema y devuelve su salida."""
        try:
            resultado = subprocess.check_output(comando, shell=True, stderr=subprocess.STDOUT, text=True)
            return resultado
        except subprocess.CalledProcessError as e:
            return f"Error ejecutando {comando}: {e.output}"

    def menu_logs(self):
        """Menú principal de análisis de logs con interfaz mejorada."""
        while True:
            self.console.clear()
            
            tabla = Table(title="Análisis de Logs")
            tabla.add_column("Opción", style="cyan")
            tabla.add_column("Descripción", style="magenta")
            
            tabla.add_row("1", "Análisis Simple de Logs")
            tabla.add_row("2", "Análisis Avanzado de Logs")
            tabla.add_row("3", "Análisis por Tipo de Log")
            tabla.add_row("4", "Comandos del Sistema")
            tabla.add_row("5", "Salir")

            self.console.print(Panel(tabla, expand=False))
            
            opcion = input("\n🔍 Selecciona una opción [1-5]: ")

            if opcion == '1':
                self.analizar_logs_simple()
            elif opcion == '2':
                self.analizar_logs_avanzado()
            elif opcion == '3':
                self.analizar_logs_por_tipo()
            elif opcion == '4':
                self.ejecutar_comandos_sistema()
            elif opcion == '5':
                break
            else:
                self.console.print("[bold red]Opción inválida.[/bold red]")
                input("Presiona Enter para continuar...")

    def analizar_logs_simple(self):
        """Análisis simple de logs con mejor presentación y uso de ejecutar_comando."""
        logs_importantes = [
            ("/var/log/auth.log", "Logs de Autenticación"),
            ("/var/log/syslog", "Logs del Sistema"),
            ("/var/log/kern.log", "Logs del Kernel")
        ]

        for ruta, titulo in logs_importantes:
            self.console.print(f"\n[bold yellow]{titulo}[/bold yellow]")
            
            # Usar ejecutar_comando para obtener las últimas 20 líneas
            comando = f"tail -n 20 {ruta}"
            salida = self.comando_log(comando)
            
            if "Error ejecutando" in salida:
                self.console.print(f"[red]{salida}[/red]")
            else:
                self.console.print(f"[dim]{salida}[/dim]")

        input("\n🔍 Análisis completado. Presiona Enter...")

    def analizar_logs_avanzado(self):
        """Análisis avanzado con búsqueda de patrones y uso de ejecutar_comando."""
        self.console.print("[bold green]Análisis Avanzado de Logs[/bold green]")
        
        patrones = {
            "Errores Críticos": ["error", "critical", "fatal"],
            "Intentos de Acceso": ["failed", "invalid", "unauthorized"],
            "Eventos de Sistema": ["started", "stopped", "restarted"]
        }

        for patron, palabras in patrones.items():
            self.console.print(f"\n[bold blue]{patron}[/bold blue]")
            for ruta in ["/var/log/syslog", "/var/log/auth.log"]:
                # Usar ejecutar_comando con grep para buscar patrones
                comando = f"grep -iE '{('|'.join(palabras))}' {ruta}"
                salida = self.comando_log(comando)
                
                if salida and "Error ejecutando" not in salida:
                    self.console.print(f"[red]📍 Resultados en {ruta}:[/red]")
                    self.console.print(f"[red]{salida}[/red]")

        input("\n🔍 Análisis avanzado completado. Presiona Enter...")

    def analizar_logs_por_tipo(self):
        """Análisis específico por tipo de log."""
        tipos_logs = {
            "1": ("/var/log/auth.log", "Logs de Autenticación"),
            "2": ("/var/log/syslog", "Logs del Sistema"),
            "3": ("/var/log/kern.log", "Logs del Kernel"),
            "4": ("/var/log/apache2/access.log", "Logs de Apache"),
            "5": ("/var/log/nginx/access.log", "Logs de Nginx")
        }

        self.console.print("[bold cyan]Selecciona un tipo de Log:[/bold cyan]")
        for key, (_, nombre) in tipos_logs.items():
            self.console.print(f"{key}. {nombre}")

        opcion = input("\nElige una opción: ")
        if opcion in tipos_logs:
            ruta, nombre = tipos_logs[opcion]
            self.console.print(f"\n[bold yellow]{nombre}[/bold yellow]")
            
            if os.path.exists(ruta):
                with open(ruta, 'r') as archivo:
                    lineas = archivo.readlines()
                    total_lineas = len(lineas)
                    
                    self.console.print(f"📊 Total de líneas: [bold green]{total_lineas}[/bold green]")
                    self.console.print("Últimas 50 líneas:")
                    
                    for linea in lineas[-50:]:
                        self.console.print(f"[dim]{linea.strip()}[/dim]")
            else:
                self.console.print(f"[red]El archivo {ruta} no existe.[/red]")
        
        input("\n🔍 Análisis completado. Presiona Enter...")

    def ejecutar_comandos_sistema(self):
        """Menú para ejecutar comandos del sistema útiles para análisis."""
        while True:
            self.console.clear()
            tabla = Table(title="Comandos del Sistema")
            tabla.add_column("Opción", style="cyan")
            tabla.add_column("Comando", style="magenta")
            tabla.add_column("Descripción", style="green")
            
            comandos = {
                "1": ("df -h", "Espacio en disco"),
                "2": ("free -h", "Uso de memoria"),
                "3": ("top -b -n 1", "Procesos en ejecución"),
                "4": ("netstat -tuln", "Puertos abiertos"),
                "5": ("systemctl status", "Estado de servicios"),
                "6": ("Volver al menú principal",)
            }

            for key, (comando, *descripcion) in comandos.items():
                if descripcion:
                    tabla.add_row(key, comando, descripcion[0])
                else:
                    tabla.add_row(key, comando, "")

            self.console.print(Panel(tabla, expand=False))
            
            opcion = input("\n Selecciona un comando [1-6]: ")

            if opcion == '6':
                break
            
            if opcion in comandos:
                comando = comandos[opcion][0]
                self.console.print(f"\n[bold yellow]Ejecutando: {comando}[/bold yellow]")
                
                # Usar ejecutar_comando para mostrar resultados
                salida = self.comando_log(comando)
                self.console.print(f"[dim]{salida}[/dim]")
                
                input("\n🔍 Presiona Enter para continuar...")
            else:
                self.console.print("[bold red]Opción inválida.[/bold red]")
                input("Presiona Enter para continuar...")


#-------------------------------------------------------------------------------------------------------------------------------------------------------

#netdiscover
def escaneo_red_local():
    # Implementar el escaneo de la red local
    salida = ejecutar_comando("ip -o -f inet addr show | awk '/scope global/ {print $4}'")
    if not salida:
        print('no se pudo detectar la direccion automaticamente')
        salida = input('Introduce la direccion de red: ')
    try:
        subprocess.call(f"netdiscover -r {salida}", shell=True)
    except Exception as e:
        print(f'Error: {e}')

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#escaneo simple, sin ser agresivo ni intrusivo con nmap
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

###   MEJORAR ESTO
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
        f.write(f"{ejecutar_comando('  iptables -L')}\n")
        f.write("----------------------------\n")
        f.write("Estado de Fail2Ban:\n")
        f.write(f"{ejecutar_comando('  fail2ban-client status sshd')}\n")
        f.write("----------------------------\n")
        f.write("Últimos logs de SSH:\n")
        f.write(f"{ejecutar_comando('  tail -n 100 /var/log/auth.log')}\n")
        f.write("----------------------------\n")
        f.write("Últimos logs del sistema:\n")
        f.write(f"{ejecutar_comando('  tail -n 100 /var/log/syslog')}\n")
        f.write("----------------------------\n")
        f.write("Uso de Disco:\n")
        f.write(f"{ejecutar_comando('df -h')}\n")
        f.write("----------------------------\n")
        f.write("Uso de Memoria:\n")
        f.write(f"{ejecutar_comando('free -h')}\n")
    
    print(f"Reporte generado: {nombre_reporte}")
    input('\nPresiona Enter para continuar...')

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#generamos un reporte del sistema actual con lynis
def escanear_vulnerabilidades():
    """Realiza un escaneo de vulnerabilidades del sistema usando Lynis."""
    
    print("\033c", end="")  # Equivalente a 'clear' en Bash para limpiar la pantalla
    print("*******************************************")
    print("* Escaneo de Vulnerabilidades del Sistema *")
    print("*******************************************\n")
    print("Puede tardar unos minutos...\n")

    # Ejecutar Lynis y guardar el reporte
    reporte = "lynis_report.txt"
    ejecutar_comando(f"lynis audit system > {reporte}")

    print("Escaneo completado. El informe se ha guardado en lynis_report.txt.")
    print("*****************************")
    print("El informe de vulnerabilidades puede ser revisado en el archivo 'lynis_report.txt'.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Funciones para cada opción del menú de fail2ban
def ver_configuracion_fail2ban():
    os.system('clear')

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
    

    print("**************************************")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

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
    subprocess.run(["netfilter-persistent", "save"], check=True)
    print("Configuración inicial del firewall aplicada.")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Menu principal
def main():
    """Función principal para ejecutar el script."""
    while True:
        os.system('clear')
        opcion = mostrar_menu_principal()

        if opcion == "configurar_firewall":
            configurar_firewall()

        elif opcion == "configurar_fail2ban":
            configurar_fail2ban()

        elif opcion == "mitigar_ddos":
            mitigar_ddos()

        elif opcion == "escaneo_puertos":
            escaneo_puertos()

        elif opcion == "monitoreo_trafico":
            monitoreo_trafico()

        elif opcion == "analizar_logs":
                analyzer = LogAnalyzer()
                analyzer.menu_logs()

        elif opcion == "escaneo_red_local":
            escaneo_red_local()

        elif opcion == "escaneo_red_externa":
            escaneo_red_externa()

        elif opcion == "generar_reporte":
            generar_reporte()

        elif opcion == "escanear_vulnerabilidades":
            escanear_vulnerabilidades()

        elif opcion == "eliminar_reglas":
            eliminar_reglas()

        elif opcion == "salir":
            ejecutar_comando("netfilter-persistent save")
            print("Saliendo del script.")
            break

        else:
            print("Opción inválida. Intenta de nuevo.")

        input("Presiona Enter para continuar...")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#menu firewall
def configurar_firewall():
    """Configuracion del firewall"""
    while True:
        os.system('clear')
        opcion_firewall = mostrar_menu_firewall()

        if opcion_firewall == 'configuracion_inicial':
            configuracion_inicial()
        elif opcion_firewall == 'reglas_de_puertos':
            reglas_de_puertos()
        elif opcion_firewall == 'bloquear_ip':
            bloquear_ip()
        elif opcion_firewall == 'permitir_ip':
            permitir_ip()
        elif opcion_firewall == 'permitir_rango_ip':
            permitir_rango_ip()
        elif opcion_firewall == 'denegar_rango_ip':
            denegar_rango_ip()
        elif opcion_firewall == 'ver_reglas_firewall':
            ver_reglas_firewall()
            input("Presiona Enter para continuar...")
            ejecutar_comando("netfilter-persistent save")

        elif opcion_firewall == 'limpiar_reglas':
            limpiar_reglas(False)
            input("Presiona Enter para continuar...")
        elif opcion_firewall == 'eliminar_reglas':
            eliminar_reglas()
        elif opcion_firewall == 'volver':
            return
        else:
            print("Opción inválida. Intenta de nuevo.")
        input("Presiona Enter para continuar...")
        optimizar_firewall()

#-------------------------------------------------------------------------------------------------------------------------------------------------------

#menu de reglas de puertos
def reglas_de_puertos():
    """Reglas de puertos"""
    while True:
        os.system('clear')
        opcion_puertos = mostrar_menu_reglas_puertos()

        if opcion_puertos == 'permitir_puerto':
            permitir_puerto()
        elif opcion_puertos == 'cerrar_puerto':
            cerrar_puerto()
        elif opcion_puertos == 'volver':
            return
        else:
            print("Opción inválida. Intenta de nuevo.")
        optimizar_firewall()

#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Menu de configuración de Fail2Ban
def configurar_fail2ban():
    """Muestra el menú de configuración de Fail2Ban."""
    while True:
        os.system('clear')
        opcion_fail2ban = mostrar_menu_fail2ban()

        if opcion_fail2ban == "configurar_fail2ban_ssh":
            configurar_fail2ban_ssh()
        elif opcion_fail2ban == "ver_configuracion_fail2ban":
            ver_configuracion_fail2ban()
        elif opcion_fail2ban == "VIPB":
            VIPB()
        elif opcion_fail2ban == "desactivar_fail2ban":
            desactivar_fail2ban()
        elif opcion_fail2ban == "desbanear_IP":
            desbanear_IP()
        elif opcion_fail2ban == "volver":
            break
        else:
            print("Opción inválida. Intenta de nuevo.")
        input("Presiona Enter para continuar...")

#-------------------------------------------------------------------------------------------------------------------------------------------------------

# Funciones placeholder para las opciones del menú principal
if __name__ == "__main__":
    main()
