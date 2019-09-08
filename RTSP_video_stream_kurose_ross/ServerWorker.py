from random import randint
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import threading, socket, hashlib, uuid, os

from VideoStream import VideoStream
from RtpPacket import RtpPacket

class ServerWorker:
	CREATE = 'CREATE'
	LOGIN = 'LOGIN'
	PLAY = 'PLAY'
	PAUSE = 'PAUSE'
	EXIT = 'EXIT'

	ESTABLISHED = 0
	READY = 1
	PLAYING = 2
	state = ESTABLISHED

	OK_200 = 0
	FILE_NOT_FOUND_404 = 1

	userDatabase = 'userDatabase.txt'
	clientInfo = {}
	
	def __init__(self, clientInfo, aes_key):
		self.clientInfo = clientInfo
		self.aesgcm = AESGCM(aes_key)
		
	def run(self):
		threading.Thread(target=self.recvRtspRequest).start()

	def recvRtspRequest(self):
		# Receive RTSP request from the client.
		connSocket = self.clientInfo['rtspSocket'][0]
		while True:
			while True:
				enc_req = connSocket.recv(1024)
				if enc_req:
					break
			while True:
				nonce = connSocket.recv(1024)
				if nonce:
					req = self.aesgcm.decrypt(nonce, enc_req, None)
					print("Data received:\n" + req.decode("utf-8"))
					self.processRtspRequest(req.decode("utf-8"))
					break

	def processRtspRequest(self, data):
		"""Process RTSP request sent from the client."""
		# Get the request type
		request = data.split('\n')
		line1 = request[0].split(' ')
		requestType = line1[0]
		
		# Get the media file name
		filename = line1[1]
		
		# Get the RTSP sequence number 
		seq = request[1].split(' ')
		
		# Process SETUP request
		if requestType == self.CREATE or requestType == self.LOGIN:
			if self.state == self.ESTABLISHED:
				line4 = request[3].split(' ')
				user = line4[1]
				line5 = request[4].split(' ')
				password = line5[1]
				try:
					self.clientInfo['videoStream'] = VideoStream(filename)
				except IOError:
					self.replyRtsp(self.FILE_NOT_FOUND_404, seq[1])
				
				# Generate a randomized RTSP session ID
				self.clientInfo['session'] = randint(100000, 999999)

				# Get the RTP/UDP port from the last line
				self.clientInfo['rtpPort'] = request[2].split(' ')[4]

				if requestType == self.CREATE:
					self.createAccount(self.userDatabase, user, password)
					print("User ", user, " successfully created account.\n")
					# Send RTSP reply
					self.state = self.READY
					self.replyRtsp(self.OK_200, seq[1])
				elif requestType == self.LOGIN:
					userFound = self.findUser(self.userDatabase, user, password)
					if userFound:
						print("User ", user, " successfully logged in.\n")
						self.state = self.READY
						self.replyRtsp(self.OK_200, seq[1])
					else:
						print("Could not find user ", user, ".\n")
						self.replyRtsp(self.FILE_NOT_FOUND_404, seq[1])

		# Process PLAY request 		
		elif requestType == self.PLAY:
			if self.state == self.READY:
				print("processing PLAY\n")
				self.state = self.PLAYING
				
				# Create a new socket for RTP/UDP
				self.clientInfo["rtpSocket"] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				
				self.replyRtsp(self.OK_200, seq[1])
				
				# Create a new thread and start sending RTP packets
				self.clientInfo['event'] = threading.Event()
				self.clientInfo['worker'] = threading.Thread(target=self.sendRtp)
				self.clientInfo['worker'].start()
		
		# Process PAUSE request
		elif requestType == self.PAUSE:
			if self.state == self.PLAYING:
				print("processing PAUSE\n")
				self.state = self.READY
				
				self.clientInfo['event'].set()
			
				self.replyRtsp(self.OK_200, seq[1])
		
		# Process TEARDOWN request
		elif requestType == self.EXIT:
			print("processing TEARDOWN\n")

			self.clientInfo['event'].set()
			
			self.replyRtsp(self.OK_200, seq[1])
			
			# Close the RTP socket
			self.clientInfo['rtpSocket'].close()
			
	def sendRtp(self):
		"""Send RTP packets over UDP."""
		while True:
			self.clientInfo['event'].wait(0.05) 
			
			# Stop sending if request is PAUSE or TEARDOWN
			if self.clientInfo['event'].isSet(): 
				break 
				
			frame = self.clientInfo['videoStream'].nextFrame()
			if frame:
				frameNumber = self.clientInfo['videoStream'].frameNbr()
				nonce = os.urandom(12)
				enc_frame = self.aesgcm.encrypt(nonce, frame, None)
				try:
					address = self.clientInfo['rtspSocket'][1][0]
					port = int(self.clientInfo['rtpPort'])
					self.clientInfo['rtpSocket'].sendto(self.makeRtp(enc_frame, frameNumber), (address, port))
					self.clientInfo['rtpSocket'].sendto(nonce, (address, port))
				except:
					print("Connection Error")

	def makeRtp(self, payload, frameNbr):
		"""RTP-packetize the video data."""
		version = 2
		padding = 0
		extension = 0
		cc = 0
		marker = 0
		pt = 26 # MJPEG type
		seqnum = frameNbr
		ssrc = 0 
		
		rtpPacket = RtpPacket()
		
		rtpPacket.encode(version, padding, extension, cc, seqnum, marker, pt, ssrc, payload)
		
		return rtpPacket.getPacket()

	def replyRtsp(self, code, seq):
		# Send RTSP reply to the client.
		if code == self.OK_200:
			reply = 'RTSP/1.0 200 OK\n'
		elif code == self.FILE_NOT_FOUND_404:
			reply = 'RTSP/1.0 404 ERROR\n'
		reply += 'CSeq: ' + seq + '\nSession: ' + str(self.clientInfo['session'])
		connSocket = self.clientInfo['rtspSocket'][0]
		nonce = os.urandom(12)
		enc_rep = self.aesgcm.encrypt(nonce, reply.encode(), None)
		connSocket.send(enc_rep)
		connSocket.send(nonce)

	def createAccount(self, userData, username, userPwd):
		f = open(userData, 'a+')
		salt = uuid.uuid4().hex
		hashed_pwd = hashlib.sha256(userPwd.encode() + salt.encode()).hexdigest()
		newEntry = '\n' + username + ' ' + salt + ' ' + hashed_pwd
		f.write(newEntry)
		f.close()

	def findUser(self, userData, username, userPwd):
		f = open(userData)
		userInfo = f.readlines()
		userNum = 1
		userFound = False
		while not userFound and userNum < len(userInfo):
			user = userInfo[userNum].split(' ')
			if username == user[0]:
				salt = user[1]
				hash_pwd = hashlib.sha256(userPwd.encode() + salt.encode()).hexdigest()
				if hash_pwd == user[2]:
					userFound = True
				else:
					userNum += 1
			else:
				userNum += 1
		return userFound
