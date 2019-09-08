from tkinter import *
import tkinter.messagebox
import PIL
from PIL import ImageTk, Image
import socket, threading, os, sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509

from RtpPacket import RtpPacket

CACHE_FILE_NAME = "cache-"
CACHE_FILE_EXT = ".jpg"

class Client:
	INIT = 0
	ESTABLISHED = 1
	READY = 2
	PLAYING = 3
	state = INIT

	SETUP = 0
	CREATE = 1
	LOGIN = 2
	PLAY = 3
	PAUSE = 4
	EXIT = 5

	# Initiation..
	def __init__(self, playBox, serveraddr, serverport, rtpport, filename):
		self.playBox = playBox
		self.playBox.protocol("WM_DELETE_WINDOW", self.playHandler)
		self.serverAddr = serveraddr
		self.serverPort = int(serverport)
		self.connectToServer()
		self.rtpPort = int(rtpport)
		self.filename = filename
		self.rtspSeq = 0
		self.sessionId = 0
		self.requestSent = -1
		self.exitAcked = 0
		self.frameNbr = 0
		with open('serv_cert.pem', 'rb') as cert_file:
			cert = x509.load_pem_x509_certificate(cert_file.read(), backend=default_backend())
		self.ca_pk = cert.public_key()
		self.setupClient()
		self.createWidgets()

	def createWidgets(self):
		# Build GUI.
		self.createButton = Button(self.playBox, width=20, padx=3, pady=3)
		self.createButton["text"] = "Create Account"
		self.createButton["command"] = self.createAccount
		self.createButton.grid(row=1, column=0, padx=2, pady=2)
		self.createButton.configure(background='steel blue')

		self.logButton = Button(self.playBox, width=20, padx=3, pady=3)
		self.logButton["text"] = "Login"
		self.logButton["command"] = self.loginUser
		self.logButton.grid(row=1, column=1, padx=2, pady=2)
		self.logButton.configure(background='steel blue')

		# Create Play button
		self.start = Button(self.playBox, width=20, padx=3, pady=3)
		self.start["text"] = "Play"
		self.start["command"] = self.playMovie
		self.start.grid(row=1, column=2, padx=2, pady=2)
		self.start.configure(background='steel blue')

		# Create Pause button
		self.pause = Button(self.playBox, width=20, padx=3, pady=3)
		self.pause["text"] = "Pause"
		self.pause["command"] = self.pauseMovie
		self.pause.grid(row=1, column=3, padx=2, pady=2)
		self.pause.configure(background='steel blue')

		# Create Teardown button
		self.exitButton = Button(self.playBox, width=20, padx=3, pady=3)
		self.exitButton["text"] = "Exit"
		self.exitButton["command"] = self.exitClient
		self.exitButton.grid(row=1, column=4, padx=2, pady=2)
		self.exitButton.configure(background='steel blue')

		self.currStatus = StringVar()
		self.statusLabel = Label(self.playBox, textvariable=self.currStatus)
		self.currStatus.set("Status:\nCreate Account or Login")
		self.statusLabel.grid(row=0,column=0)

		self.currUser = StringVar()
		self.userLabel = Label(self.playBox, textvariable=self.currUser)
		self.currUser.set("User:\nNone")
		self.userLabel.grid(row=0, column=4)

		# Create a label to display the movie
		self.label = Label(self.playBox, height=19)
		self.label.grid(row=0, column=1, columnspan=3, sticky=W + E + N + S, padx=5, pady=5)

	def setupClient(self):
		if self.state == self.INIT:
			self.generateAESkey()

	def exitClient(self):
		"""Teardown button handler."""
		self.sendRtspRequest(self.EXIT)
		self.playBox.destroy() # Close the gui window
		os.remove(CACHE_FILE_NAME + str(self.sessionId) + CACHE_FILE_EXT) # Delete the cache image from video

	def pauseMovie(self):
		"""Pause button handler."""
		if self.state == self.PLAYING:
			self.sendRtspRequest(self.PAUSE)
	
	def playMovie(self):
		"""Play button handler."""
		if self.state == self.READY:
			# Create a new thread to listen for RTP packets
			threading.Thread(target=self.listenRtp).start()
			self.playEvent = threading.Event()
			self.playEvent.clear()
			self.sendRtspRequest(self.PLAY)

	def createAccount(self):
		if self.state == self.ESTABLISHED:
			self.username = input("Enter username for account: ")
			self.password = input("Enter password for account: ")
			self.sendRtspRequest(self.CREATE)

	def loginUser(self):
		if self.state == self.ESTABLISHED:
			self.username = input("Enter username for account: ")
			self.password = input("Enter password for account: ")
			self.sendRtspRequest(self.LOGIN)

	def generateAESkey(self):
		self.rtspSocket.send(b'Connection Request')
		while True:
			cert_data = self.rtspSocket.recv(1024)
			if cert_data:
				cert = x509.load_pem_x509_certificate(cert_data, backend=default_backend())
				sig = cert.signature
				cert_bytes = cert.tbs_certificate_bytes
				self.ca_pk.verify(sig, cert_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
				self.aes_key = AESGCM.generate_key(bit_length=128)
				self.aesgcm = AESGCM(self.aes_key)
				enc_key = self.ca_pk.encrypt(self.aes_key,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(),label=None))
				self.rtspSocket.send(enc_key)
				while True:
					conf = self.rtspSocket.recv(1024)
					if conf:
						if conf.decode() == "Connection Established":
							self.state = self.ESTABLISHED
							break
				break
		print("Key Exchange Completed")

	def listenRtp(self):
		# Listen for RTP packets.
		while True:
			try:
				while True:
					enc_frame = self.rtpSocket.recv(20480)
					if enc_frame:
						rtpPacket = RtpPacket()
						rtpPacket.decode(enc_frame)
						break
				while True:
					nonce = self.rtpSocket.recv(1024)
					if nonce:
						frame = self.aesgcm.decrypt(nonce, rtpPacket.getPayload(), None)
						currFrameNbr = rtpPacket.seqNum()
						print("Current Seq Num: " + str(currFrameNbr))
						break

				if currFrameNbr > self.frameNbr:  # must be new packet
					self.frameNbr = currFrameNbr
					self.updateMovie(self.writeFrame(frame))
			except:
				# Stop listening upon requesting PAUSE or TEARDOWN
				if self.playEvent.isSet():
					break

				# Upon receiving ACK for TEARDOWN request,
				# close the RTP socket
				if self.exitAcked == 1:
					self.rtpSocket.shutdown(socket.SHUT_RDWR)
					self.rtpSocket.close()
					break

	def writeFrame(self, data):
		"""Write the received frame to a temp image file. Return the image file."""
		cachename = CACHE_FILE_NAME + str(self.sessionId) + CACHE_FILE_EXT
		file = open(cachename, "wb")
		file.write(data)
		file.close()
		
		return cachename
	
	def updateMovie(self, imageFile):
		"""Update the image file as video frame in the GUI."""
		photo = PIL.ImageTk.PhotoImage(PIL.Image.open(imageFile))
		self.label.configure(image = photo, height=288) 
		self.label.image = photo
		
	def connectToServer(self):
		"""Connect to the Server. Start a new RTSP/TCP session."""
		self.rtspSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			self.rtspSocket.connect((self.serverAddr, self.serverPort))
		except:
			tkinter.messagebox.showwarning('Connection Failed', 'Connection to \'%s\' failed.' %self.serverAddr)

	def sendRtspRequest(self, requestCode):
		"""Send RTSP request to the server."""
		# Create account request
		if requestCode == self.CREATE and self.state == self.ESTABLISHED:
			threading.Thread(target=self.recvRtspReply).start()
			# Update RTSP sequence number.
			self.rtspSeq += 1
			# Write the RTSP request to be sent.
			request = 'CREATE'
			# Keep track of the sent request.
			self.requestSent = self.CREATE
		# Login request
		elif requestCode == self.LOGIN and self.state == self.ESTABLISHED:
			threading.Thread(target=self.recvRtspReply).start()
			# Update RTSP sequence number.
			self.rtspSeq += 1
			# Write the RTSP request to be sent.
			request = 'LOGIN'
			# Keep track of the sent request.
			self.requestSent = self.LOGIN
		# Play request
		elif requestCode == self.PLAY and self.state == self.READY:
			# Update RTSP sequence number.
			self.rtspSeq += 1
			# Write the RTSP request to be sent.
			request = 'PLAY'
			# Keep track of the sent request.
			self.requestSent = self.PLAY
		# Pause request
		elif requestCode == self.PAUSE and self.state == self.PLAYING:
			# Update RTSP sequence number.
			self.rtspSeq += 1
			# Write the RTSP request to be sent.
			request = 'PAUSE'
			# Keep track of the sent request.
			self.requestSent = self.PAUSE
		# Teardown request
		elif requestCode == self.EXIT and not self.state == self.ESTABLISHED:
			# Update RTSP sequence number.
			self.rtspSeq += 1
			# Write the RTSP request to be sent.
			request = 'EXIT'
			# Keep track of the sent request.
			self.requestSent = self.EXIT
		else:
			return
		# Send the RTSP request using rtspSocket.
		RTSPreq = request + ' ' + str(self.filename) + ' RTSP/1.0\nCSeq: ' + str(self.rtspSeq) + '\nTransport: RTP/UDP; client port= ' + str(self.rtpPort)
		if request == 'CREATE' or request == 'LOGIN':
			RTSPreq += '\nUser: ' + str(self.username) + '\nPassword: ' + str(self.password)
		nonce = os.urandom(12)
		enc_req = self.aesgcm.encrypt(nonce, RTSPreq.encode(), None)
		self.rtspSocket.send(enc_req)
		self.rtspSocket.send(nonce)
		print('\nData sent:\n' + request)

	def recvRtspReply(self):
		# Receive RTSP reply from the server.
		while True:
			while True:
				enc_rep = self.rtspSocket.recv(1024)
				if enc_rep:
					break
			while True:
				nonce = self.rtspSocket.recv(1024)
				if nonce:
					reply = self.aesgcm.decrypt(nonce, enc_rep, None)
					self.parseRtspReply(reply.decode("utf-8"))
					break

			# Close the RTSP socket upon requesting Teardown
			if self.requestSent == self.EXIT:
				self.rtspSocket.shutdown(socket.SHUT_RDWR)
				self.rtspSocket.close()
				break

	def parseRtspReply(self, data):
		"""Parse the RTSP reply from the server."""
		lines = data.split('\n')
		seqNum = int(lines[1].split(' ')[1])
		
		# Process only if the server reply's sequence number is the same as the request's
		if seqNum == self.rtspSeq:
			session = int(lines[2].split(' ')[1])
			# New RTSP session ID
			if self.sessionId == 0:
				self.sessionId = session

			# Process only if the session ID is the same
			if self.sessionId == session:
				if int(lines[0].split(' ')[1]) == 200:
					if self.requestSent == self.CREATE or self.requestSent == self.LOGIN:
						# Update RTSP state.
						self.state = self.READY
						self.currUser.set("User:\n" + self.username)
						self.currStatus.set("Status:\nReady to Play")
						# Open RTP port.
						self.openRtpPort()
						if self.requestSent == self.CREATE:
							print("User ", self.username, " successfully created account.\n")
						elif self.requestSent == self.LOGIN:
							print("User ", self.username, " successfully logged in.\n")
					elif self.requestSent == self.PLAY:
						self.state = self.PLAYING
						self.currStatus.set("Status:\nPlaying")
					elif self.requestSent == self.PAUSE:
						self.state = self.READY
						self.currStatus.set("Status:\nReady to Play")
						# The play thread exits. A new thread is created on resume.
						self.playEvent.set()
					elif self.requestSent == self.EXIT:
						# Flag the exitAcked to close the socket.
						self.exitAcked = 1
				elif int(lines[0].split(' ')[1]) == 404:
					print("ERROR: Invalid credentials or MJPEG filename. Terminating...")
					self.playBox.destroy()
					self.rtspSocket.shutdown(socket.SHUT_RDWR)
					sys.exit()

	def openRtpPort(self):
		"""Open RTP socket binded to a specified port."""
		# Create a new datagram socket to receive RTP packets from the server
		self.rtpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		
		# Set the timeout value of the socket to 0.5sec
		self.rtpSocket.settimeout(0.5)
		
		try:
			# Bind the socket to the address using the RTP port given by the client user
			self.rtpSocket.bind(('127.0.0.1', self.rtpPort))
		except:
			tkinter.messagebox.showwarning('Unable to Bind', 'Unable to bind PORT=%d' %self.rtpPort)


	def playHandler(self):
		"""Handler on explicitly closing the player GUI window."""
		self.pauseMovie()
		if tkinter.messagebox.askokcancel("Quit?", "Are you sure you want to quit?"):
			self.exitClient()
		else: # When the user presses cancel, resume playing.
			self.playMovie()
