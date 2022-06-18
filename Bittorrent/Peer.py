from threading import Thread
import sys, getopt, os
import socket
import json
import time

class Peer:
    def __init__(self, info_file):
        self.info = json.loads(open(info_file).read())
        self.available_torrents = self.list_files()
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.recv_data = []

    def list_files(self):
        temp_list = []
        for i in os.listdir(self.info['root_dir']):
            if(i.endswith('.torrent')):
                temp_list.append(i)
        return temp_list
    
    def im_alive(self):
        msg = {'id': self.info['peer_id'], 'ip': self.info['ip'], 'port': self.info['port'], 'available_torrents': self.available_torrents ,'msg': 'ALIVE'}
        self.peer_socket.connect(("localhost", int(self.info['tracker_port'])))
        self.peer_socket.send(json.dumps(msg).encode('utf-8'))
        response = self.peer_socket.recv(1024).decode('utf-8')
    
    def get_peers(self, tracker_down):
        if tracker_down:
            return False
        msg = {'id': self.info['peer_id'], 'msg': 'GET_PEERS'}
        self.peer_socket.send(json.dumps(msg).encode('utf-8'))
        temp = self.peer_socket.recv(1024).decode('utf-8')
        if(temp == ''):
            print("The tracker is down")
            return False
        self.recv_data = json.loads(temp)
        self.recv_data.pop('msg')
        self.recv_data.pop(self.info['peer_id'])
        return True

    def update_status(self, tracker_down):
        if tracker_down:
            return False
        self.available_torrents = self.list_files()
        msg = {'id': self.info['peer_id'], 'ip': self.info['ip'], 'port': self.info['port'], 'available_torrents': self.available_torrents ,'msg': 'UPDATE_STATUS'}
        self.peer_socket.send(json.dumps(msg).encode('utf-8'))
        temp = self.peer_socket.recv(1024).decode('utf-8')
        if(temp == ''):
            print("F por el Tracker")
            return False
        else:
            return True

    def reconnect(self):
        try:
            self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.im_alive()
            return True
        except ConnectionRefusedError:
            print("F por el Tracker")
            return False

    def print_peers(self):
        for peer in self.recv_data:
            print("Peer: " + peer)
            print("IP: " + self.recv_data[peer]['ip'])
            print("Puerto: " + self.recv_data[peer]['port'])
            print("Torrents Disponibles: " + str(self.recv_data[peer]['available_torrents']))

class S_Peer:
    def __init__(self, info_file):
        self.info = json.loads(open(info_file).read())
        self.sr_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sr_socket.bind((self.info['ip'], int(self.info['port'])))
        self.sr_socket.listen(2)
        self.continue_running = True
        self.PIECE_LENGTH = 10240
    
    def listen(self):
        while self.continue_running:
            conn, addr = self.sr_socket.accept()
            if conn:
                self.process_request(conn)
    
    def process_request(self, request):
        data = request.recv(1024).decode('utf-8')
        data = json.loads(data)
        if data['msg'] == 'GET_TORRENT':
            self.send_file(request, data['requested_torrest'])
        elif data['msg'] == 'TERMINATE' and data['id'] == self.info['peer_id']:
            self.continue_running = False
    
    def send_file(self, request, file_name):
        json_name = open(self.info['root_dir'] + "/"+file_name)
        json_file = json.load(json_name)
        request.send(json.dumps(json_file).encode('utf-8'))
        response = request.recv(1024).decode('utf-8')
        response = json.loads(response)
        if(response['msg'] == 'OK'):
            current_file = open(json_file['name'], "rb")
            piece = current_file.read(self.PIECE_LENGTH)
            while piece:
                request.send(piece)
                piece = current_file.read(self.PIECE_LENGTH)
                if not piece:
                    break
            request.close()
            current_file.close()

def handle_connection(info_file):

    peer_obj = Peer(info_file)
    peer_obj.im_alive()
    tracker_down = False
    while True:
        if(tracker_down):
            if(peer_obj.reconnect()):
                tracker_down = False
        print(f"~~~~~~~~~~Menu~~~~~~~~~~")        
        print(f"1. Torrents Disponibles")
        print(f"2. Descargar el Torrent")
        print(f"3. Actualizar Torrents")
        print(f"4. Salir")
        choice = input(f"Seleccione una opción: ")
        if(choice == "1"):
            if(peer_obj.get_peers(tracker_down)):
                if(len(peer_obj.recv_data) == 0):
                    print("No hay Peer disponibles")
                else:
                    peer_obj.print_peers()
            else:
                print("No hay Peer disponibles")
                tracker_down = True
                peer_obj.peer_socket.close()
        elif(choice == "2"):
            if(not len(peer_obj.recv_data) == 0):
                print("Ingresa la ID del Peer que deseas descargar: ")
                peer_id = input()
                if(peer_id not in peer_obj.recv_data):
                    print("ID del Peer Invalido")
                    continue
                print(f"Ingresa el nombre del torrent a descargar: ")
                torrent_name = input()
                if(torrent_name not in peer_obj.recv_data[peer_id]['available_torrents']):
                    print("Nombre del Torrent Inválido")
                    continue
                print("Conectando con el Peer...")
                msg = {'id': peer_obj.info['peer_id'], 'ip': peer_obj.info['ip'], 'port': peer_obj.info['port'], 'requested_torrest': torrent_name, 'msg': 'GET_TORRENT'}
                try:
                    r_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    r_socket.connect((peer_obj.recv_data[peer_id]['ip'], int(peer_obj.recv_data[peer_id]['port'])))
                    r_socket.send(json.dumps(msg).encode('utf-8'))
                    response = r_socket.recv(1024).decode('utf-8')
                    if(response):
                        r_socket.send(json.dumps({'id': peer_obj.info['peer_id'], 'msg': 'OK'}).encode('utf-8'))
                        data = json.loads(response)
                        new_file = open(data['name'], "wb")
                        piece = r_socket.recv(10240)
                        print("Descargando...")
                        while piece:
                            new_file.write(piece)
                            piece = r_socket.recv(10240)
                        new_file.close()
                        r_socket.close()
                        print("Descarga Completa")
                except ConnectionRefusedError:
                    print("Peer Desconectado")
                    print("Por favorrrrr, recarga la lista de Peers")
                    continue
            else:
                print("No hay Peers disponibles")
        elif(choice == "3"):
            print("Actualizando Status...")
            if(peer_obj.update_status(tracker_down)):
                print("Status actualizado")
            else:
                print("Tracker Desmayao")
                tracker_down = True
                print("Por favor, try again more tarde")
        elif(choice == "4"):
            print(f"Saliending")
            if(tracker_down):
                try:
                    socket_close = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_close.connect((peer_obj.info['ip'], int(peer_obj.info['port'])))
                    msg = {'id': peer_obj.info['peer_id'], 'msg': 'TERMINATE'}
                    socket_close.send(json.dumps(msg).encode('utf-8'))
                    socket_close.close()
                except ConnectionRefusedError:
                    break
                break
            else:
                try:
                    socket_close = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_close.connect((peer_obj.info['ip'], int(peer_obj.info['port'])))
                    msg = {'id': peer_obj.info['peer_id'], 'msg': 'TERMINATE'}
                    socket_close.send(json.dumps(msg).encode('utf-8'))
                    socket_close.close()
                    msg = {'id': peer_obj.info['peer_id'], 'msg': 'OFFLINE'}
                    peer_obj.peer_socket.send(json.dumps(msg).encode('utf-8'))
                    peer_obj.peer_socket.close()
                except ConnectionRefusedError:
                    break
                break
        else:
            print(f"Elección Invalida")
    
def handle_s_peer(info_file):
    peer_s_obj = S_Peer(info_file)
    peer_s_obj.listen()
    peer_s_obj.sr_socket.close()

def validate_file(file):

    if(not os.path.exists(file)):
        return False
    return True

def main(argv):

    try:
        opts,args = getopt.getopt(argv, "vhp:r:i:", ["verbose","help", "info_file="])
    except getopt.GetoptError:
        print("Argumentos Invalidos")
        sys.exit(2)
    verbose_mode = False
    info_file = ""
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("Modo de uso: python Torrent.py [-h] [-v] [-i <info_file>]")
            print("-h, --Ayuda : -v, --verbose : -i, --info_file (Peer)")
            sys.exit()
        elif opt in ("-v", "--verbose"):
            verbose_mode = True
        elif opt in ("-i", "--info_file"):
            info_file = arg
            if(not validate_file(info_file)):
                print("[Error]: Información de Archivo Invalida")
                sys.exit()
    thread1 = Thread(target=handle_connection, args=(info_file,))
    thread2 = Thread(target=handle_s_peer, args=(info_file,))
    thread1.start()
    thread2.start()

if __name__ == "__main__":
    main(sys.argv[1:])