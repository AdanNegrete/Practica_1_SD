import sys, getopt
import os.path
import net_tools as nt
import hashlib
import math
import json

class Torrent:

    def __init__(self, name, tracker_port, tracker_ip):

        self.id = hashlib.md5(name.encode('utf-8')).hexdigest()
        self.name = name
        self.tracker_port = tracker_port
        self.tracker_ip = tracker_ip
        self.pieces = 0
        self.last_piece_size = 0
        self.check_sum = []

    def __str__(self):
 
        json_data = {
            "id": self.id,
            "name": self.name,
            "tracker_port": self.tracker_port,
            "tracker_ip": self.tracker_ip,
            "pieces": self.pieces,
            "last_piece_size": self.last_piece_size,
            "check_sum": self.check_sum
        }
        return str(json_data)


def validate_file(file):
    if(not os.path.exists(file)):
        return False
    return True
    
def main(argv):
    
    try:
        opts,args = getopt.getopt(argv, "vhp:i:f:", ["verbose","help", "port=", "ip=", "file="])
    except getopt.GetoptError as err:
        print('[Error]: ' + str(err))
        print("Modo de Uso: python Torrent.py [-h] [-v] [-p <port> -i <ip> -f <file>]")
        print("-h, --help : -v, --verbose : -p, --port : -i, --ip : -f, --file")
        sys.exit(2)
    curre_file = ""
    verbose_mode = False
    if(len(args) > 0):
        print("Argumentos Invalidos: " + str(args))
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("Modo de Uso: python Torrent.py [-h] [-v] [-p <port> -i <ip> -f <file>]")
            print("-h, --help : -v, --verbose : -p, --port : -i, --ip : -f, --file")
            sys.exit()
        elif opt in ("-p", "--port"):
            tracker_port = arg
            if(not nt.validate_port(tracker_port)):
                print("[Error]: Puerto Invalido")
                sys.exit()
        elif opt in ("-i", "--ip"):
            tracker_ip = arg
            if(not nt.validate_ip(tracker_ip)):
                print("[Error]: IP Invalida")
                sys.exit()
        elif opt in ("-f", "--file"):
            current_file_path = arg
            if(not validate_file(current_file_path)):
                print("[Error]: El archivo solicitado no existe")
                sys.exit()
        elif opt in ("-v", "--verbose"):
            verbose_mode = True
    PIECE_LENGTH = 102400
    torrent = Torrent(current_file_path, tracker_port, tracker_ip)
    current_file = open(current_file_path, "rb")
    current_file_size = os.path.getsize(current_file_path)
    current_file_pieces = math.ceil(current_file_size / PIECE_LENGTH)
    last_piece_size = current_file_size - (current_file_pieces-1) * PIECE_LENGTH
    torrent.last_piece_size = last_piece_size
    torrent.pieces = current_file_pieces
    for i in range(current_file_pieces-1):
        readed_data = current_file.read(PIECE_LENGTH)
        torrent.check_sum.append(hashlib.md5(readed_data).hexdigest())
    last_readed_data = current_file.read(last_piece_size)
    torrent.check_sum.append(hashlib.md5(last_readed_data).hexdigest())
    current_file.close()
    json_format = json.dumps(torrent, default=lambda o: o.__dict__, sort_keys=True, indent=4)
    file_without_extension = current_file_path.split(".")[0]     
    open(file_without_extension + ".torrent", "w").write(json_format)
    if verbose_mode:
        print('Verbose activado, mostrando torrent en formato json')
        print(json_format)
    print("Archivo torrent creado en: " + os.path.abspath(file_without_extension) + ".torrent")

if __name__ == "__main__":
    main(sys.argv[1:])
