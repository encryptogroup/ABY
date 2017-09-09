#Definition of the interrupt handler routine. Invoked when Ctrl+c/z is encountered.
exitfn () {
    trap SIGINT              
	echo 'killing client'
    kill $CLIENT_PID
    exit                    
}

trap "exitfn" INT            # Set up SIGINT trap to call function.

./bin/test-aby.exe -r 0 &
CLIENT_PID=$!
./bin/test-aby.exe -r 1
	
