def validate_ip(ip):

    if(len(ip.split(".")) != 4):
        return False
    for i in ip.split("."):
        if(not i.isdigit() or int(i) < 0 or int(i) > 255):
            return False
    return True

def validate_port(port):

    if(not port.isdigit()):
        return False
    if(int(port) < 0 or int(port) > 65535):
        return False
    return True