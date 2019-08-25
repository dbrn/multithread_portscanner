from threading import Thread, Lock
import socket
import argparse

# This is a multi-threaded port-scanner with file-writing lock


def scan(hostname, start, end, write, filename, timeout):
    lock = Lock()
    for port in range(start, end + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((hostname, port))
        except socket.timeout:
            s.close()
            continue
        except ConnectionRefusedError:
            s.close()
            print(f"connection refused by server on port {port}")
            continue
        s.close()
        if write is True:

            # We acquire a lock in order to avoid multiple threads to write
            # on the same file
            lock.acquire()
            with open(filename, "a") as file:
                file.write(f"{port} OPEN\n")

            # when we are done writing we release the lock
            lock.release()
        print(f"{port} OPEN")


def main():
    timeout = 0.5
    writing = False

    # These are the mandatory arguments: hostname, starting port, ending port
    # Optional arguments are: output to file, number of threads and time-out
    # See program.py -h for more infos
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", type=str)
    parser.add_argument("startingport", help="the port where portscanning will start", type=int)
    parser.add_argument("endingport", help="the port where scanning will end", type=int)
    parser.add_argument("-o", "--output", nargs=1, type=str, help="output to file")
    parser.add_argument("-t", "--threads", nargs=1, type=int, help="Number of threads to run")
    parser.add_argument("-to", "--timeout", nargs=1, type=float)
    args = parser.parse_args()

    # if we have an argument for the time-out set it
    if args.timeout is not None:
        timeout = args.timeout[0]
    hostname = args.hostname
    start_port = args.startingport
    end_port = args.endingport

    # If we want to write to a file, set the switch (writing) to True
    if args.output is not None:
        writing = True
        with open(args.output[0], "a") as file:
            file.write(f"Port-scan on {hostname} in port range {start_port}-{end_port}\n")
    print(f"Port-scan on {hostname} in port range {start_port}-{end_port}")

    # If we are running a multi-threaded scan divide the number of ports
    # equally among each thread, and add the remainder to the last one
    if args.threads is not None:
        num_threads = args.threads[0]
        port_num = (end_port - start_port)
        if num_threads > port_num:
            num_threads = port_num
        print(f"{num_threads} threads requested")
        remainder = port_num % num_threads
        port_per_thread = int(port_num // num_threads)
        for i in range(num_threads):
            s_port = (i * port_per_thread) + start_port
            e_port = s_port + port_per_thread - 1
            if i == num_threads - 1:
                e_port += remainder + 1
            print(f"Thread {i}:{s_port}-{e_port}")
            if writing is True:
                thread = Thread(target=scan, args=(hostname, s_port, e_port, writing, args.output[0], timeout))
            else:
                thread = Thread(target=scan, args=(hostname, s_port, e_port, writing, "", timeout))
            thread.start()

    # else check if we want to write and execute the scan function accordingly
    elif writing is True:
        scan(hostname, start_port, end_port, writing, args.output[0], timeout)
    else:
        scan(hostname, start_port, end_port, writing, "", timeout)


if __name__ == "__main__":
    main()
