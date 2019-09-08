import sys, socket
from ServerWorker import ServerWorker
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

with open('serv_cert.pem', 'rb') as cert_file:
	cert = x509.load_pem_x509_certificate(cert_file.read(), backend=default_backend())

with open('serv_sk.pem', 'rb') as sk_file:
	sk = serialization.load_pem_private_key(sk_file.read(), password=None, backend=default_backend())

class Server:

	def main(self):
		try:
			SERVER_PORT = int(sys.argv[1])
		except:
			print("[Usage: Server.py Server_port]\n")
		rtspSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		rtspSocket.bind(('127.0.0.1', SERVER_PORT))
		rtspSocket.listen(5)        

		# Receive client info (address,port) through RTSP/TCP session
		while True:
			clientInfo = {}
			clientInfo['rtspSocket'] = rtspSocket.accept()
			connSocket = clientInfo['rtspSocket'][0]
			while True:
				initMess = connSocket.recv(1024)
				if initMess:
					if initMess.decode() == "Connection Request":
						connSocket.send(cert.public_bytes(encoding=serialization.Encoding.PEM))
						while True:
							enc_key = connSocket.recv(1024)
							if enc_key:
								break
						break
			connSocket.send(b'Connection Established')
			aes_key = sk.decrypt(enc_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
			ServerWorker(clientInfo, aes_key).run()


if __name__ == "__main__":
	(Server()).main()

