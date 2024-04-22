import socket
import json

def sendToSyslogCollector (json_data):

    # Define the syslog collector's IP address and port
    collector_ip = '192.168.56.105'
    collector_port = 6675  # The default syslog port is 514

    # JSON data to be sent

    # Convert JSON data to a string
    json_string = json.dumps(json_data)

    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the collector
    sock.connect((collector_ip, collector_port))

    # Send the JSON-formatted syslog message over the TCP connection
    sock.sendall(json_string.encode('utf-8'))

    # Close the socket
    sock.close()

def main():
    json_data = {
    "timestamp": "2023-09-20T12:00:00",
    "message": "This is a JSON syslog message from Python (without encryption over TCP)."
    }

    sendToSyslogCollector(json_data)
    
    
if __name__ == '__main__':
    main()