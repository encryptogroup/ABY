#!/usr/bin/python

##immport socket module v
import socket
import sys, getopt


def main(argv):
        value = 2
        try:
                opts, args = getopt.getopt(argv,"hv:",["value="])
        except getopt.GetoptError:
                print 'client.py -v <value> '
                sys.exit(2)
        for opt, arg in opts:
                if opt == '-h':
                        print 'client.py -v <value>'
                        sys.exit()
                elif opt in ("-v", "--value"):
                        value = arg

  ## print 'Input file is "', inputfile
  ## print 'Output file is "', outputfile

  ## Do socket things
  # Create a socket object 
        s = socket.socket()

  # Define the port on which you want to connect 
        port = 12345

  # connect to the server on local computer 
        s.connect(('172.17.0.4', port))

  #send data
        s.send(value);

  # receive data from the server 
        print s.recv(1024)
  # close the connection 
        s.close()

if __name__ == "__main__":
   main(sys.argv[1:])
