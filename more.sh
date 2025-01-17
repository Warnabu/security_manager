
controlar_acceso_directorios() {
    echo "Estableciendo controles de acceso..."
    chmod 700 /etc /var/log
    chown root:root /etc /var/log
    echo "Controles de acceso establecidos."
}
escaneo_servicios_vulnerables() {
    echo "Escaneando puertos y servicios vulnerables..."
    nmap -sV --script vuln 127.0.0.1
    echo "Escaneo completado."
}
controlar_acceso_directorios() {
    echo "Estableciendo controles de acceso..."
    chmod 700 /etc /var/log
    chown root:root /etc /var/log
    echo "Controles de acceso establecidos."
}
backup_configuraciones() {
    echo "Realizando backup de configuraciones..."
    tar -czf /backup/config_backup_$(date +%Y%m%d).tar.gz /etc/iptables /etc/fail2ban /etc/ssh/sshd_config
    echo "Backup completado."
}
deteccion_malware() {
    echo "Buscando malware o rootkits..."
    apt-get install chkrootkit
    chkrootkit
    echo "Análisis completado."
}
monitoreo_integridad() {
    echo "Iniciando monitoreo de integridad..."
    apt-get install aide
    aideinit
    echo "Monitoreo de integridad iniciado."
}