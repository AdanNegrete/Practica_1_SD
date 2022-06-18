import sys, getopt
import os.path
import net_tools as nt
import hashlib
import json

def main(argv):
    
    try:
        opts,args = getopt.getopt(argv, "hp:r:i:t:", ["help", "port=", "ip=","root=", "tracker="])
    except getopt.GetoptError:
        print("[Error] Argumentos Invalidos")
        sys.exit(2)
    if args:
        print("[Error] Argumentos Invalidos: " + str(args))
        sys.exit(2)
    tracker_port = ""
    peer_port = ""
    root_dir = ""
    ip = ""
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("Modo de Uso: python3 Torrent.py -p <port> -i <ip> -r <root> -t <tracker>")
            print("-p, --puerto : -i, --ip : -r, --root : -t, --tracker")
            sys.exit()
        elif opt in ("-p", "--port"):
            peer_port = arg
            if(not nt.validate_port(peer_port)):
                print("[Error]: Puerto Invalido")
                sys.exit()
        elif opt in ("-i", "--ip"):
            ip = arg
            if(not nt.validate_ip(ip)):
                print("[Error]: IP Invalida")
                sys.exit()
        elif opt in ("-r", "--root"):
            root_dir = arg
            if(not os.path.exists(root_dir)):
                print("[Error]: Directorio Root Invalido")
                sys.exit()
        elif opt in ("-t", "--tracker"):
            tracker_port = arg
            if(not nt.validate_port(tracker_port)):
                print("[Error]: Puerto Invalido")
                sys.exit()
    if(peer_port == "" or root_dir == "" or ip == "" or tracker_port == ""):
        print("[Error]: Faltan Argumentos")
        sys.exit(2)
    peer_info = {"peer_id": hashlib.md5(root_dir.encode('utf-8')).hexdigest(), "port": str(peer_port), "ip": str(ip),"root_dir": root_dir, "tracker_port": str(tracker_port)}
    open("{}/peer_info{}.json".format(root_dir,hashlib.md5(root_dir.encode('utf-8')).hexdigest()), "w").write(json.dumps(peer_info))
if __name__ == "__main__":
    main(sys.argv[1:])