from threading import Thread
from time import sleep
import net_tools as nt
import sys, getopt
import json
import socket

peers_control = {}

def handle_peer(peer_socket):

    while True:
        data = peer_socket.recv(1024).decode('utf-8')
        if not data:
            continue
        else:
            data = json.loads(data)
        print("Received: " + str(data))
        if data['msg'] == "GET_PEERS":
            if len(peers_control) == 0:
                msg = {'id': data['id'], 'msg': 'NO_PEERS'}
                peer_socket.send(json.dumps(msg).encode('utf-8'))
            else:
                temp_list = peers_control.copy()
                temp_list['msg'] = 'AVAILABLE_PEERS'
                peer_socket.send(json.dumps(temp_list).encode('utf-8'))
        elif data['msg'] == "ALIVE":
            peer_socket.send("Hello {}".format(data['id']).encode('utf-8'))
            id_data = data['id']
            data.pop('id')
            data.pop('msg')
            data['status'] = 'ALIVE'
            peers_control[id_data] = data
        elif data['msg'] == "UPDATE_STATUS":
            id_data = data['id']
            data.pop('id')
            data.pop('msg')
            data['status'] = 'ALIVE'
            peers_control[id_data] = data
            msg = {'id': id_data, 'msg': 'STATUS_UPDATED'}
            peer_socket.send(json.dumps(msg).encode('utf-8'))
        elif data['msg'] == "OFFLINE":
            peers_control.pop(data['id'])

def threaded_tracker(tracker_port):

    tracker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tracker_socket.bind(("0.0.0.0", tracker_port))
    tracker_socket.listen(5) # 5 is the max number of queued connections, 0 means no limit
    while True:
        peer_socket, peer_address = tracker_socket.accept()
        print(f"Esperando conexiones...")
        if peer_socket:
            print("Cliente conectado: " + str(peer_address))
            Thread(target=handle_peer, args=(peer_socket,)).start()

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "vhp:", ["verbose","help", "port="])
    except getopt.GetoptError:
        print("Argumentos Inválidos")
        sys.exit(2)
    tracker_port = ""
    verbose_mode = False
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("Modo de Uso: python Tracker_handler.py [-h] [-v] [-p <port>]")
            print("-h, --help : -v, --verbose : -p, --port")
            sys.exit()
        elif opt in ("-p", "--port"):
            tracker_port = arg
            if(not nt.validate_port(tracker_port)):
                print("[Error]: Puerto Invalido")
                sys.exit()
        elif opt in ("-v", "--verbose"):
            verbose_mode = True
    threaded_tracker(int(tracker_port))
if __name__ == "__main__":
    main(sys.argv[1:])