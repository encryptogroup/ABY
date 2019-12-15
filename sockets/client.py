#!/usr/bin/python


## This file will open to connections with two different servers. Will send a+alpha to one server and -alpha
## to the other,  where alpha is a random number.

## The addresses are hardcoded and just useful for my environment. Same for the port numbers.
##immport socket module v
import socket                
import sys, getopt
from random import randrange

def main(argv):
        random= randrange(11)
        value = 2
        fAddress = '172.17.0.4'
        sAddress = '172.17.0.5'
        try:
                opts, args = getopt.getopt(argv,"hv:a:",["value=","address="])
        except getopt.GetoptError:
                print 'client.py -v <value> -a <address> '
                sys.exit(2)
        for opt, arg in opts:
                if opt == '-h':
                        print 'client.py -v <value>'
                        sys.exit()
                elif opt in ("-v", "--value"):
                        value = int(arg)
                elif opt in ("-a","--address"):
                        print 'baba'  

## print 'Input file is "', inputfile
  ## print 'Output file is "', outputfile

  ## Do socket things
  # Create a socket object 
        s = socket.socket()          
  
  # Define the port on which you want to connect 
        port = 12345                
  
  # connect to the server on local computer 
        s.connect((fAddress, port)) 

  #send data A to ALICE. So we need to send -random to BOB
        eValue = value+ random
        s.send(str(eValue));
  

        s.close
        s = socket.socket()
        s.connect((sAddress, port))
        eValueB = 0-random
        s.send(str(eValueB))
  # receive data from the server 
        #print s.recv(1024) 
  # close the connection 


        s.close()



if __name__ == "__main__":
   main(sys.argv[1:])
