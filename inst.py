#!/usr/bin/env python3

import os
import subprocess
import shutil
import sys

# Verificar si el script se ejecuta como root
if os.geteuid() != 0:
    print("Este script debe ejecutarse como root o con sudo.")
    sys.exit(1)

# Lista de los paquetes necesarios del sistema
packages = ["nmap", "iftop", "iptables", "fail2ban", "net-tools", "lynis", "netdiscover", "iptables-persistent"]

# Lista de los paquetes de Python necesarios (pip)
python_packages = ["inquirer"]

# Función para verificar si un comando existe
def comando_existe(comando):
    try:
        subprocess.run([comando, "--version"], check=False, capture_output=True)
        return True
    except FileNotFoundError:
        return False

# Verificar si Python 3 está instalado
if not comando_existe("python3"):
    print("Error: Python 3 no está instalado.")
    sys.exit(1)

# Obtener la ruta al directorio del script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Define la ruta del entorno virtual dentro del directorio del script
venv_path = os.path.join(script_dir, ".venv")
pip_executable = os.path.join(venv_path, "bin", "pip")
python_executable = os.path.join(venv_path, "bin", "python3")
script_dst = "/usr/local/bin/security_manager"


# Función para crear y activar un entorno virtual
def crear_entorno_virtual():
    """Crea un entorno virtual si no existe."""
    if not os.path.exists(venv_path):
        print(f"Creando entorno virtual en {venv_path}...")
        try:
            subprocess.run(["python3", "-m", "venv", venv_path], check=True)
            print("Entorno virtual creado correctamente.")
        except subprocess.CalledProcessError as e:
            print(f"Error al crear el entorno virtual: {e}")
            sys.exit(1)
    else:
        print("El entorno virtual ya existe.")

# Función para instalar paquetes con pip dentro del entorno virtual
def instalar_paquetes_pip():
    """Instala los paquetes de Python utilizando pip."""
    if not os.path.exists(pip_executable):
        print(f"Error: pip no se encuentra en el entorno virtual.")
        sys.exit(1)

    print(f"Instalando dependencias de Python con pip en {venv_path}...")
    try:
        subprocess.run([pip_executable, "install", "--upgrade", "pip"], check=True, capture_output=True, text=True)
        subprocess.run([pip_executable, "install", *python_packages], check=True, capture_output=True, text=True)
        print("Dependencias de Python instaladas correctamente.")
    except subprocess.CalledProcessError as e:
        print(f"Error al instalar las dependencias de Python: {e.stderr}")
        sys.exit(1)

def modificar_shebang():
    script_src = "security_manager.py"
    
    if os.path.exists(script_src):
        try:
            # Leer el contenido del script
            with open(script_src, 'r') as file:
                content = file.readlines()
            
            # Modificar la primera línea (shebang)
            content[0] = f"#!/usr/bin/env python3\n"
            
            # Escribir el contenido modificado de nuevo al archivo
            with open(script_src, 'w') as file:
                file.writelines(content)
            
            print(f"Shebang en {script_src} modificado para usar la ruta local de python3.")
        except Exception as e:
            print(f"Error al modificar el shebang en {script_src}: {e}")
    else:
        print(f"Advertencia: No se encontró '{script_src}'.")

def copiar_script():
    """Copia el script principal y le da permisos de ejecución."""
    script_src = "security_manager.py"
    script_dst_venv = os.path.join(venv_path, "bin", "security_manager")

    if os.path.exists(script_src):
        # Usar el intérprete del entorno virtual en el shebang
        try:
            with open(script_src, 'r') as file:
                content = file.readlines()
            content[0] = f"#!/usr/bin/env python3\n"  # Env force the use of .venv
            with open(script_src, 'w') as file:
                file.writelines(content)
        except Exception as e:
            print(f"Error al modificar el shebang en {script_src}: {e}")
        
        shutil.copy(script_src, script_dst_venv)
        os.chmod(script_dst_venv, 0o755)  # Dar permisos de ejecución
        print(f"El script ha sido instalado correctamente como 'security_manager'. Puedes ejecutarlo con el comando '{script_dst_venv}'.")
    else:
        print(f"Advertencia: No se encontró '{script_src}', no se ha copiado.")

    # Crear un script de inicio en /usr/local/bin
    symlink_dst = "/usr/local/bin/security_manager"
    if not os.path.exists(symlink_dst):
        try:
            os.symlink(script_dst_venv, symlink_dst)
            print(f"Se ha creado un enlace simbólico en {symlink_dst} para ejecutar el script globalmente.")
        except OSError as e:
            print(f"No se pudo crear el enlace simbólico en /usr/local/bin: {e}")
            print(f"Puedes ejecutar el script directamente desde {script_dst_venv}")
    else:
        print(f"Ya existe un enlace simbólico en {symlink_dst}.")

# Función para instalar dependencias del sistema
def instalar_dependencias_sistema():
    """Instala las dependencias del sistema."""
    print("Instalando dependencias necesarias del sistema...")
    try:
        subprocess.run(["apt-get", "update"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["apt-get", "install", "-y"] + packages, check=True)
        print("Dependencias del sistema instaladas correctamente.")
    except subprocess.CalledProcessError as e:
        print(f"Error al instalar las dependencias del sistema: {e}")
        sys.exit(1)

# Función principal para ejecutar el script
def main():
    """Función principal para ejecutar el script."""
    instalar_dependencias_sistema()
    crear_entorno_virtual()
    instalar_paquetes_pip()
    modificar_shebang()
    copiar_script()

    print("Instalación completada.")

if __name__ == "__main__":
    main()
