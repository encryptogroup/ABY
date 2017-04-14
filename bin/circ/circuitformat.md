# .ABY circuit format

_v0.1 - 2017-04-13_

This circuit format can be parsed by the [ABY framework](https://github.com/encryptogroup/ABY). It was used to implement (among others) floating point gates, which were generated and optimized using hardware synthesis tools. Details on that can be found in [our CCS'15 paper](http://dl.acm.org/citation.cfm?id=2813678).

This circuit format is similar to human-readable [Bristol format](https://www.cs.bris.ac.uk/Research/CryptographySecurity/MPC/), but a bit simpler.
The differences to the bristol format are
* We currently assume all gates to have a fixed number of input wires, so we do not need to encode this info.
* The files are sorted topologically, i.e., gates are defined strictly in order from input to output, or put differently, a wire id is always defined or written to before it is read or output.
* The gate type (operation) is the first character in each line, to simplify parsing.

Note that this circuit format is by no means perfect or stable and might be changed, extended or altered in the future.

## Wire Declarations
Every bit or wire has an individual wire ID. Every wire can be inputs to arbitrarily many gates.
The notation for wires is `WIRE ID0 [ID1 …]`, where `WIRE` is a single character and `IDx` is an integer number.

### Input Wires
Input wires specifically denote the wire IDs which have the be input into the circuit from the outside.
It was originally intended to specify within the circuit which of the 2 parties (client/server, thus `C`/`S`) provides which input wire.
Later this idea was dropped but the syntax is still in the ABY files. Currently both definitions are parsed and handled equally.

`C 0 1 2` or equally `S 0 1 2` denotes input wires with labels 0, 1, and 2, that receive inputs from outside of the circuit. Usually these start from 0 and are the lowest wire IDs in the circuit.

### Output Wires
`O 101 102 103` denotes the three output wire labels 101, 102, and 103. We assume that 101, 102 and 103 are at some point defined as inputs or outputs from function gates. Usually output wires have the highest wire IDs in the circuit. These are used to specifically hint what meaningful circuit outputs are. In principle, every wire ID could be an output.

### Constant Wire
`0 -2` and `1 -3` denote the constant zero and one wires with IDs -2 and -3, respectively. They need only be defined once and are typically hard-coded.


## Function Gate Types

The notation we use for function gates is
`GATE IN0 [IN1] [IN2] OUT`
, where `GATE` is currently a single character and `INx`, `OUT` are integer wire IDs. In other words, inputs are listed first and the right-most wire ID is the output that is written.

### XOR gate
`X 101 102 103` denotes 103 = 101 XOR 102 (where we assume 101 and 102 to be defined at some earlier point in the file).

### AND gate
`A 101 102 103` denotes 103 = 101 AND 102 (where we assume 101 and 102 to be defined at some earlier point in the file).

### MUX gate
`M 101 102 103 104` denotes 104 = 103 ? 102 : 101. (where we assume 101, 102, 103, and 104 to be defined at some earlier point in the file). More precisely, 103 is the selection bit, which selects the input 101 or 102 which is written to 104. If 103 is true, then 104 = 102, else 104 = 101.

### Inversion gate
`I 101 102` denotes that 102 = NOT 101, i.e. the negation or inversion of the Boolean value of 101 is written to 102.


## Comments
Every character at the beginning of a line that does not denote one of the previously mentioned gate types (`0`, `1`, `A`, `C`, `I`, `M`, `O`, `S`, `X`) is simply ignored. However, we followed the convention to begin comment lines with a `#` symbol. Some .aby files contain measured gate counts at the beginning of the file or some sort of description.


## Usage with ABY
In order to use the built-in methods for floating-point computation in ABY, the circuit files must be placed in a subdirectory `circ`, which must be located in the same directory as the executable.

### Floating-point circuit files
Most floating-point gates come in different bit lengths of 16, 42, and 64 bit precision. Gates are available as full IEEE version, that includes status outputs that denote division by zero, overflows, etc. FP circuits denoted with _nostatus_ do not contain these outputs and are thus marginally smaller.

All circuits are optimized for both low depth and low number of AND gates, with a priority on low-depth, i.e. there might be gates that have a lower number of AND gates but higher depth.
