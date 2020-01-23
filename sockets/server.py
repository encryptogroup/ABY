## Created by llorencroma

## It will write just one received line to the provided file or 'demo.txt' as default. 
## If we want to write more than one line, use --append option.


##first of  all import the socket library 
import socket                
import sys, getopt

def main(argv):
        fileName ='demo.txt' ## default file.
        option = 'w+'
        try:
                opts, args = getopt.getopt(argv,"hf:a",["file=","append"])
        except getopt.GetoptError:
                print 'server.py -f <file> [-a]'
                sys.exit(2)
        for opt, arg in opts:
                if opt == '-h':
                        print 'server.py -f <file> [option] '
                        print '-a --append Append received data to the file. Otherwise the file will be overwritten'
                        sys.exit()
                elif opt in ("-f", "--file"):
                        fileName = arg

                elif opt in  ("-a","--append"):
                        option = 'a+'




  
# Next bind a socket object 
        s = socket.socket()
        print "Socket successfully created"

# reserve a port on your computer in our 
# case it is 12345 but it can be anything 
        port = 12345

# we have not typed any ip in the ip field 
# instead we have inputted an empty string 
# this makes the server listen to requests  
# coming from other computers on the network 
        s.bind(('', port))         
        print "socket binded to %s" %(port) 
  
# put the socket into listening mode 
        s.listen(5)      
        print "socket is listening"            
  
# a forever loop until we interrupt it or  
# an error occurs 
        while True: 
  
   # Establish connection with client. 
                c, addr = s.accept()      
                from_client= ''
                f = open(fileName,option)
                print 'Got connection from', addr 
                while True:
                        data = c.recv(4096)
                        if not data: break
                        from_client += data+"\n"
                        f.write(from_client)
   # send a thank you message to the client.  
                # c.send('Thank you for connecting') 

   # Close the connection with the client 
                c.close()

if __name__ == "__main__":
        main(sys.argv[1:]) 
