# security_manager
security_manager
# Security Manager Script

Este script de gestión de seguridad está diseñado para ayudar a administrar y asegurar sistemas Linux mediante el uso de herramientas como `iptables`, `fail2ban`, `nmap`, y otras utilidades de red. Permite realizar tareas como la configuración del firewall, análisis de vulnerabilidades, protección contra ataques DDoS, y la gestión de reglas de firewall de manera fácil e interactiva.

## Funcionalidades

1. **Gestión de Reglas de Firewall (iptables)**:
    - Permite agregar, eliminar y listar reglas en el firewall.
    - Aplica reglas de seguridad como limitar el número de conexiones por IP, cerrar puertos, bloquear IPs específicas, etc.
    - Hace las reglas persistentes para que sobrevivan a los reinicios del sistema.

2. **Protección contra DDoS**:
    - Implementa medidas para bloquear ataques DDoS utilizando `iptables`, como limitar conexiones por IP y prevenir conexiones SYN excesivas.

3. **Análisis de Vulnerabilidades**:
    - Realiza un análisis de vulnerabilidades en el sistema utilizando `Lynis`, un escáner de seguridad, para identificar posibles debilidades.
    - Permite hacer un escaneo de puertos con `nmap` para verificar posibles puntos de ataque en la red local.

4. **Protección con Fail2Ban**:
    - Configura y activa `fail2ban` para proteger el sistema de intentos de acceso no autorizado mediante el bloqueo de IPs con múltiples intentos fallidos.

5. **Análisis y Gestión de Logs**:
    - Permite analizar los logs del sistema de manera detallada o simplificada, para ayudar a detectar posibles eventos o accesos no autorizados.

6. **Escaneo de Red Local**:
    - Utiliza `netdiscover` y `nmap` para escanear la red local en busca de dispositivos conectados, proporcionando información sobre las IPs y servicios activos.

7. **Persistencia de Reglas**:
    - Todas las configuraciones realizadas con `iptables` se hacen persistentes, asegurando que las reglas se mantengan incluso después de un reinicio del sistema.

## Instalación

1. **Clonar el repositorio**:

``bash
git clone https://github.com/tu_usuario/security_manager.git
cd security_manager


    Ejecutar el script de instalación:

El script instalará todas las dependencias necesarias (como nmap, iptables, fail2ban, entre otras) y copiará el script principal a /usr/local/bin/ para que puedas ejecutarlo desde cualquier ubicación. Asegúrate de ejecutar este script como root o utilizando sudo:

sudo bash install.sh

El script se encargará de:

    Actualizar los repositorios de tu sistema.
    Instalar las dependencias necesarias.
    Copiar el script principal (security_manager.sh) a una ubicación accesible.

Uso

    Ejecutar el script:
        Para ejecutar el script, simplemente corre el siguiente comando:

sudo security_manager

Interfaz interactiva:

El script proporcionará un menú interactivo donde podrás seleccionar diversas opciones de seguridad:

    Elige una opción:
    1) Configurar firewall
    2) Protege contra DDoS
    3) Realizar análisis de vulnerabilidades
    4) Administrar Fail2Ban
    5) Analizar logs del sistema
    6) Escanear red local
    7) Escanear puertos con Nmap
    8) Guardar reglas
    9) Salir

    Solo sigue las instrucciones en pantalla para configurar las opciones de seguridad.

Contribuciones

Si tienes ideas para nuevas funcionalidades o mejoras, ¡estaremos encantados de recibir tus contribuciones! Solo asegúrate de seguir las buenas prácticas de código y abrir un pull request.
Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo LICENSE para más detalles.


### Explicación del `README.md` actualizado:

- **Instalación**: Se ha añadido la sección para ejecutar el script `install.sh` que se encarga de instalar las dependencias automáticamente, de forma que el usuario no tenga que preocuparse de instalar nada manualmente. El script se ocupa de todo.
  
- **Dependencias**: Ahora no es necesario que el usuario instale manualmente las dependencias, ya que el script `install.sh` lo hace por él.


