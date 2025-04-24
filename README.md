This is a chat room which has features like username, text exchange, 
file transfers(all sorts of files including audio and videos), 
along with emojis and secured with SSL.
The history of all chats will be saved in a log file.

All the files received will be saved in Received files folder.


Use the following command to download the SSL certificates
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

To run it 
first run the server code
then run the client code according to the number of clients.

