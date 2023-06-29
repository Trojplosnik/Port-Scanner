import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def check_tcp_port(port: int, host: str = "127.0.0.1") -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.01)
    result = sock.connect_ex((host, port))
    if result == 0:
        return port
    return -1


def check_udp_port(port: int, host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.01)
        try:
            sock.sendto(b'', (host, port))
            data, _ = sock.recvfrom(1024)
            return -1
        except socket.timeout:
            return port
        except socket.error:
            return -1


def scanner(check_func, host: str = "127.0.0.1",
            first_port: int = 0, last_port: int = 65535) -> list[int]:
    open_ports = []
    if first_port < 0 or last_port > 65535:
        return open_ports
    with ThreadPoolExecutor(500) as executor:
        ports = range(first_port, last_port + 1)
        results = [executor.submit(check_func, host=host, port=port) for port in ports]
        for f in as_completed(results):
            if f.result() >= 0:
                open_ports.append(f.result())
    return sorted(open_ports)


def main():
    ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    port_pattern = re.compile(r'\d+')
    if len(sys.argv) == 1:
        print("open TSP ports:")
        print(scanner(check_tcp_port))
        print("open UDP ports:")
        print(scanner(check_udp_port))
    elif len(sys.argv) < 5:
        if not re.search(ip_pattern, sys.argv[1]):
            print("Wrong input: incorrect ip-address")
        elif len(sys.argv) == 2:
            print("open TSP ports:")
            print(scanner(check_func=check_tcp_port, host=sys.argv[1]))
            print("open UDP ports:")
            print(scanner(check_func=check_udp_port, host=sys.argv[1]))
        elif len(sys.argv) == 3:
            if re.search(port_pattern, sys.argv[2]):
                print("open TSP ports:")
                print(scanner(check_func=check_tcp_port,
                              host=sys.argv[1],
                              last_port=int(sys.argv[2])))
                print("open UDP ports:")
                print(scanner(check_func=check_udp_port,
                              host=sys.argv[1],
                              last_port=int(sys.argv[2])))
            else:
                print("Wrong input: incorrect port range")
        elif len(sys.argv) == 4:
            if re.search(port_pattern, sys.argv[2]) \
                    and re.search(port_pattern, sys.argv[3]):
                print("open TSP ports:")
                print(scanner(check_func=check_tcp_port,
                              host=sys.argv[1],
                              first_port=int(sys.argv[2]),
                              last_port=int(sys.argv[3])))
                print("open UDP ports:")
                print(scanner(check_func=check_udp_port,
                              host=sys.argv[1],
                              first_port=int(sys.argv[2]),
                              last_port=int(sys.argv[3])))
            else:
                print("Wrong input: incorrect port range")
    else:
        print("Wrong input: too many parameters")


if __name__ == '__main__':
    main()
