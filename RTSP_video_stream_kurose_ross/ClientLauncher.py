import sys
from tkinter import Tk
from Client import Client

if __name__ == "__main__":
	try:
		serverAddr = sys.argv[1]
		serverPort = sys.argv[2]
		rtpPort = sys.argv[3]
		fileName = sys.argv[4]	
	except:
		print("[Usage: ClientLauncher.py Server_name Server_port RTP_port Video_file]\n")	
	
	player = Tk()

	# Create a new client
	app = Client(player, serverAddr, serverPort, rtpPort, fileName)

	player.title("RTP Client")
	player.configure(background='black')
	player.mainloop()
