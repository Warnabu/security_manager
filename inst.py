#!/usr/bin/env python3

import os
import subprocess
import shutil
import sys

# Verificar si el script se ejecuta como root
if os.geteuid() != 0:
    print("[x] Este script debe ejecutarse como root o con sudo.")
    sys.exit(1)

# Lista de paquetes necesarios del sistema
packages = ["nmap", "iftop", "iptables", "fail2ban", "net-tools", "lynis", "netdiscover", "iptables-persistent", "python3-pip", "python3-venv"]

# Lista de paquetes de Python (pip)
python_packages = ["inquirer", "colorama", "rich"]

# Obtener la ruta al directorio del script
script_dir = os.path.dirname(os.path.abspath(__file__))

# Definir rutas
venv_path = os.path.join(script_dir, ".venv")
pip_executable = os.path.join(venv_path, "bin", "pip")
python_executable = os.path.join(venv_path, "bin", "python3")
script_src = "security_manager.py"
script_dst = os.path.join(venv_path, "bin", "security_manager")
symlink_dst = "/usr/local/bin/security_manager"

# Función para verificar si un comando existe
def comando_existe(comando):
    return shutil.which(comando) is not None

# Verificar si Python 3 está instalado
if not comando_existe("python3"):
    print("[x]Error: Python 3 no está instalado.")
    sys.exit(1)

# Función para instalar dependencias del sistema
def instalar_dependencias_sistema():
    """Instala dependencias del sistema con apt-get."""
    print("[!] Instalando dependencias del sistema...")
    try:
        subprocess.run(["apt-get", "update"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["apt-get", "install", "-y"] + packages, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[v] Dependencias del sistema instaladas correctamente.")
    except subprocess.CalledProcessError as e:
        print(f"[x] Error al instalar dependencias del sistema: {e.stderr.decode()}")
        sys.exit(1)

# Función para crear un entorno virtual
def crear_entorno_virtual():
    """Crea un entorno virtual si no existe."""
    if not os.path.exists(venv_path):
        print(f"[!] Creando entorno virtual en {venv_path}...")
        try:
            subprocess.run(["python3", "-m", "venv", venv_path], check=True)
            print("[v] Entorno virtual creado correctamente.")
        except subprocess.CalledProcessError as e:
            print(f"[x] Error al crear el entorno virtual: {e.stderr.decode()}")
            sys.exit(1)
    else:
        print("[!] El entorno virtual ya existe.")

# Función para instalar paquetes con pip dentro del entorno virtual
def instalar_paquetes_pip():
    """Instala los paquetes de Python utilizando pip en el entorno virtual."""
    if not os.path.exists(pip_executable):
        print("[x] Error: pip no se encuentra en el entorno virtual.")
        sys.exit(1)

    print(f"[!] Instalando dependencias de Python con pip en {venv_path}...")
    try:
        subprocess.run([pip_executable, "install", "--upgrade", "pip"], check=True, text=True)
        subprocess.run([pip_executable, "install", *python_packages], check=True, text=True)
        print("[v] Dependencias de Python instaladas correctamente.")
    except subprocess.CalledProcessError as e:
        print(f"[x] Error al instalar dependencias de Python: {e.output or e.stderr}")
        sys.exit(1)

# Función para modificar el shebang del script
def modificar_shebang():
    """Modifica el shebang del script para usar Python del entorno virtual."""
    if os.path.exists(script_src):
        try:
            with open(script_src, 'r') as file:
                content = file.readlines()
            content[0] = f"#!{python_executable}\n"
            with open(script_src, 'w') as file:
                file.writelines(content)
            print(f"[v] Shebang de {script_src} modificado para usar el entorno virtual.")
        except Exception as e:
            print(f"[x] Error al modificar el shebang: {e}")
    else:
        print(f"[!] Advertencia: No se encontró '{script_src}'.")

# Función para copiar el script y dar permisos de ejecución
def copiar_script():
    """Copia el script principal y le da permisos de ejecución."""
    if os.path.exists(script_src):
        shutil.copy(script_src, script_dst)
        os.chmod(script_dst, 0o755)
        print(f"[v] Script copiado a '{script_dst}'.")
    else:
        print(f"[!] Advertencia: No se encontró '{script_src}', no se ha copiado.")

    # Crear o reemplazar el enlace simbólico en /usr/local/bin
    if os.path.exists(symlink_dst):
        os.remove(symlink_dst)  # Eliminar si ya existe
    try:
        os.symlink(script_dst, symlink_dst)
        print(f"[v] Enlace simbólico creado en {symlink_dst}.")
    except OSError as e:
        print(f"⚠️ No se pudo crear el enlace simbólico: {e}")
        print(f"[!] Puedes ejecutar el script directamente desde {script_dst}.")

# Función principal
def main():
    """Ejecuta todas las funciones de instalación."""
    instalar_dependencias_sistema()
    crear_entorno_virtual()
    instalar_paquetes_pip()
    modificar_shebang()
    copiar_script()
    print("[OK] Instalación completada.")

if __name__ == "__main__":
    main()
