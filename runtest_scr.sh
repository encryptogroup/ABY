#Definition of the interrupt handler routine. Invoked when Ctrl+c/z is encountered.
exitfn () {
    trap SIGINT
	echo 'killing client'
    kill $CLIENT_PID
    exit
}

trap "exitfn" INT            # Set up SIGINT trap to call function.

./bin/abytest -r 0 -R &
CLIENT_PID=$!
./bin/abytest -r 1 -R

