import sys, getopt
import os.path
import net_tools as nt
import hashlib
import json

def main(argv):
    """
    Main method that takes in the command line arguments and creates a torrent file
    Parameters:
        argv: The command line arguments
    """
    try:
        opts,args = getopt.getopt(argv, "hp:r:i:t:", ["help", "port=", "ip=","root=", "tracker="])
    except getopt.GetoptError:
        print("Invalid arguments")
        sys.exit(2)
    if args:
        print("Invalid arguments: " + str(args))
        sys.exit(2)
    tracker_port = ""
    peer_port = ""
    root_dir = ""
    ip = ""
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("Usage: python3 Torrent.py [-h]  [-p <port> -i <ip> -r <root> -t <tracker>]")
            print("-h, --help: Print this help message")
            print("-p, --port: Port number of the peer")
            print("-i, --ip: IP address of the peer")
            print("-r, --root: Path of the root directory")
            print("-t, --tracker: port of the tracker")
            sys.exit()
        elif opt in ("-p", "--port"):
            peer_port = arg
            if(not nt.validate_port(peer_port)):
                print("Error: Invalid port")
                sys.exit()
        elif opt in ("-i", "--ip"):
            ip = arg
            if(not nt.validate_ip(ip)):
                print("Error: Invalid ip")
                sys.exit()
        elif opt in ("-r", "--root"):
            root_dir = arg
            if(not os.path.exists(root_dir)):
                print("Error: Invalid root directory")
                sys.exit()
        elif opt in ("-t", "--tracker"):
            tracker_port = arg
            if(not nt.validate_port(tracker_port)):
                print("Error: Invalid port")
                sys.exit()
    if(peer_port == "" or root_dir == "" or ip == "" or tracker_port == ""):
        print("Error: Missing arguments")
        sys.exit(2)
    peer_info = {"peer_id": hashlib.md5(root_dir.encode('utf-8')).hexdigest(), "port": str(peer_port), "ip": str(ip),"root_dir": root_dir, "tracker_port": str(tracker_port)}
    open("{}/peer_info{}.json".format(root_dir,hashlib.md5(root_dir.encode('utf-8')).hexdigest()), "w").write(json.dumps(peer_info))
if __name__ == "__main__":
    main(sys.argv[1:])