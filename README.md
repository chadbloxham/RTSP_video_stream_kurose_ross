# RTSP_video_stream_kurose_ross
An RTSP video streamer client and server. Includes user login/account creation, CA certificate server authentication, RSA key exhcange, and AES-GCM encryption/decryption and authentication of transmitted MJPEG data. Based on code from a programming exercise in "Computer Networking: A Top-Down Approach", 7th edition by Kurose and Ross.

## Run Instructions
In a command line or terminal, start the server:

Server.py [serv port number]

where serv port number is the port number the server will use to listen for client connections and receive RTSP requests. Next, open another command line or terminal and start the client:

ClientLauncher.py [serv IP add] [serv port number] [client port number] [MJPEG filename]

serv IP add is proven to work with the loopback address 127.0.0.1. serv port number is the same as above. client port number is the port on which the client will recieve RTP video data. MJPEG filename is the name of the file which will be sent from the server.

The user interface will appear. Create an account or login by pressing either button. There is currently one username/password value in the database:

![user login](https://github.com/chadbloxham/RTSP_video_stream_kurose_ross/blob/master/userLogin.PNG)

Once login or account creation is complete, user can play video, pause video, or exit.

## Demonstration
<a href="https://imgflip.com/gif/3a158x"><img src="https://i.imgflip.com/3a158x.gif" title="made at imgflip.com"/></a>
