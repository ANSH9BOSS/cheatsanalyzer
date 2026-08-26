import socket
import struct

class RCONBridge:
    """Lightweight Minecraft server RCON bridge for one-click ban/punish enforcement."""

    def __init__(self, host="127.0.0.1", port=25575, password=""):
        self.host = host
        self.port = port
        self.password = password

    def send_command(self, command):
        """Sends an RCON command to the Minecraft server."""
        if not self.password:
            return False, "RCON Password not configured"

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect((self.host, self.port))

            # Packet format: Length (int32), Request ID (int32), Type (int32), Payload (string), 2 Null bytes
            # Type 3 = Auth
            auth_payload = struct.pack("<iii", len(self.password) + 10, 1, 3) + self.password.encode("utf-8") + b"\x00\x00"
            sock.send(auth_payload)
            resp = sock.recv(4096)

            # Type 2 = Command
            cmd_payload = struct.pack("<iii", len(command) + 10, 2, 2) + command.encode("utf-8") + b"\x00\x00"
            sock.send(cmd_payload)
            cmd_resp = sock.recv(4096)
            sock.close()

            # Parse response string
            if len(cmd_resp) >= 12:
                resp_text = cmd_resp[12:-2].decode("utf-8", errors="ignore")
                return True, resp_text or "Command executed successfully"
            return True, "Command executed"
        except Exception as e:
            return False, f"RCON Connection failed: {str(e)}"
