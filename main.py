import socket
import sys
import threading
from PyQt5 import QtWidgets as qt
from PyQt5 import QtCore as qc

class BroadcastRelayApp(qt.QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        # Create GUI components
        self.setWindowTitle("Broadcast Relay")

        self.bind_ports_label = qt.QLabel("Bind Ports (comma-separated):")
        self.bind_ports_input = qt.QLineEdit()

        self.target_ip_label = qt.QLabel("Target IP Address (e.g., 192.168.1.100):")
        self.target_ip_input = qt.QLineEdit()

        self.target_ports_label = qt.QLabel("Target Ports (comma-separated):")
        self.target_ports_input = qt.QLineEdit()

        self.start_button = qt.QPushButton("Start Relay")
        self.start_button.clicked.connect(self.start_relay)

        self.log_output = qt.QTextEdit()
        self.log_output.setReadOnly(True)

        # Layout setup
        layout = qt.QVBoxLayout()
        layout.addWidget(self.bind_ports_label)
        layout.addWidget(self.bind_ports_input)
        layout.addWidget(self.target_ip_label)
        layout.addWidget(self.target_ip_input)
        layout.addWidget(self.target_ports_label)
        layout.addWidget(self.target_ports_input)
        layout.addWidget(self.start_button)
        layout.addWidget(self.log_output)

        self.setLayout(layout)

    def log(self, message):
        # Thread-safe logging
        qc.QMetaObject.invokeMethod(self.log_output, "append", qc.Qt.QueuedConnection, qc.Q_ARG(str, message))

    def start_relay(self):
        bind_ports = self.bind_ports_input.text()
        target_ip = self.target_ip_input.text()
        target_ports = self.target_ports_input.text()

        if not bind_ports or not target_ip or not target_ports:
            self.log("Error: Please fill all fields.")
            return

        try:
            bind_ports = list(map(int, bind_ports.split(",")))
            target_ports = list(map(int, target_ports.split(",")))
            if len(bind_ports) != len(target_ports):
                self.log("Error: Bind ports and target ports must have the same number of entries.")
                return

            threading.Thread(target=retransmit_data, args=(bind_ports, target_ip, target_ports, self.log), daemon=True).start()
            self.log("Relay started.")
        except ValueError:
            self.log("Error: Ports must be integers and comma-separated.")
        except Exception as e:
            self.log(f"Error: {e}")

def retransmit_data(bind_ports, target_ip, target_ports, log_callback):
    def handle_port(bind_port, target_port):
        try:
            # Create a UDP socket to receive packets
            receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            # Bind to the specified port
            receive_socket.bind(('', bind_port))
            log_callback(f"Listening for packets on port {bind_port}...")

            # Create a UDP socket to send packets
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            while True:
                try:
                    # Receive data
                    data, addr = receive_socket.recvfrom(1024)  # Buffer size of 1024 bytes
                    log_callback(f"Received packet on port {bind_port} from {addr}: {data}")

                    # Retransmit the data to the specified IP and port
                    send_socket.sendto(data, (target_ip, target_port))
                    log_callback(f"Forwarded packet from port {bind_port} to {target_ip}:{target_port}")
                except Exception as e:
                    log_callback(f"Error in data handling on port {bind_port}: {e}")
                    break

        except Exception as e:
            log_callback(f"An error occurred on port {bind_port}: {e}")

        finally:
            receive_socket.close()
            send_socket.close()
            log_callback(f"Closed sockets for port {bind_port}.")

    threads = []
    for bind_port, target_port in zip(bind_ports, target_ports):
        thread = threading.Thread(target=handle_port, args=(bind_port, target_port), daemon=True)
        threads.append(thread)
        thread.start()

if __name__ == "__main__":
    app = qt.QApplication(sys.argv)
    window = BroadcastRelayApp()
    window.show()
    sys.exit(app.exec_())
