# [ABY](http://encrypto.de/papers/DSZ15.pdf) [![Build Status](https://travis-ci.org/encryptogroup/ABY.svg?branch=public)](https://travis-ci.org/encryptogroup/ABY)


### A Framework for Efficient Mixed-Protocol Secure Two-Party Computation

By *Daniel Demmler, Thomas Schneider and Michael Zohner* ([ENCRYPTO](http://www.encrypto.de), TU Darmstadt)<br>in [Network and Distributed System Security Symposium (NDSS'15)](http://www.internetsociety.org/events/ndss-symposium-2015). [Paper available here.](http://thomaschneider.de/papers/DSZ15.pdf)

### Features
---
ABY efficiently combines secure computation schemes based on **Arithmetic sharing**, **Boolean sharing**, and **Yao’s garbled circuits** and makes available best-practice solutions in secure two-party computation.
It allows to pre-compute almost all cryptographic operations and provides novel, highly efficient conversions between secure computation schemes based on pre-computed *oblivious transfer extensions* using our [**OT extension library**](https://github.com/encryptogroup/OTExtension) available on GitHub.
ABY supports several standard operations and provides example applications.

This code is provided as a experimental implementation for testing purposes and should not be used in a productive environment. We cannot guarantee security and correctness.

### Requirements
---

* A **Linux distribution** of your choice (ABY was developed and tested with recent versions of [Debian](https://www.debian.org/) and [Ubuntu](http://www.ubuntu.com/)).
* **Required packages for ABY:**
  * [`g++`](https://packages.debian.org/testing/g++)
  * [`make`](https://packages.debian.org/testing/make)
  * [`libgmp-dev`](https://packages.debian.org/testing/libgmp-dev)
  * [`libglib2.0-dev`](https://packages.debian.org/testing/libglib2.0-dev)
  * [`libssl-dev`](https://packages.debian.org/testing/libssl-dev)

  Install these packages with your favorite package manager, e.g, `sudo apt-get install <package-name>`.

* Optional packages: `doxygen` and `graphviz` to create your own [Doxygen](http://www.doxygen.org) documentation of the code.

### ABY Sourcecode
---

#### File System Structure

* `/bin/`    - Executables.
* `/src/`    - Source code.
 * `src/abycore/` - Source of the internal ABY functions.
 * `src/examples/` - Example applications. Each application has a `/common` directory that holds the functionality (circuit). The idea is to re-use this circuit even outside of the application. The application's root directory contains a `.cpp` file with a main method that runs the circuit and is used to verify correctness.
 * `src/test/` - Currently one application to test internal ABY functions as well as example applications and print debug information.

#### Building the ABY Framework

1. **Recursively clone** the ABY git repository (including its submodules) by running:
	```
	git clone --recursive https://github.com/encryptogroup/ABY.git
	```
Please **don't** download the .zip file, since it doesn't include submodules. Also note that there has been an update where the OT extension code has been outsourced as **submodule**. In case an older code version is updated to the current version, please run `git submodule init` and `git submodule update`.

2. Enter the Framework directory: `cd ABY/`

3. Call `make` in the root directory of ABY to compile all dependencies, tests, and examples and create the corresponding executables.

#### Makefile Options
##### Building ABY
**In most cases you should be fine with simply running `make` in the ABY root directory.** This will invoke `make all`, which will obviously build everything and is called by default. There are several options you can pass to `make` to build parts of ABY.

* `make miracl` - build the Miracl library, which is included as submodule according to their build instructions
* `make otext` - copies the [**OT extension source files**](https://github.com/encryptogroup/OTExtension) from the external repository into the internal ABY repository
* `make core` - build only the core files of ABY, requires Miracl
* `make examples` - build all examples and create executables for them, requires core
* `make test` - build the tests and create an executable, requires core

##### Testing ABY
* `make runtest` - executes the test binary for both roles in 1 terminal

##### Cleaning ABY
* `make clean` - cleans all binaries plus example and test object files
* `make cleanmore` - same as `make clean` plus ABY core object files
* `make cleanall` - same as `make cleanmore` plus Miracl and OT extension library objects

There are several compiler flags that can be set within `Makefile` for the ABY core and `Example_Makefile` for the ABY examples. There are severeal predefined optiones, that can be commented out as needed.


#### Developer Guide and Documentation
We provide an extensive [developer guide](https://www.informatik.tu-darmstadt.de/media/encrypto/encrypto_code/abydevguide.pdf) with many examples and explanations of how to use ABY.

Also, see the [online doxygen documentation of ABY](http://encryptogroup.github.io/ABY/docs/index.html) for further information and comments on the code.


### ABY Applications
---

#### Included Example Applications

  * The [**Millionaire's Problem**](http://en.wikipedia.org/wiki/Yao%27s_Millionaires%27_Problem) was proposed by Yao in 1982. Two parties want to find out who is richer, without revealing their actual wealth. This simple example can be used as starting point for your own ABY application.
  * Secure computation [**AES**](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard), where one party inputs the key and the other party inputs a message to collaboratively encrypt.
  * The [**Euclidean Distance**](https://en.wikipedia.org/wiki/Euclidean_distance) for two 2-dimensional coordinates.
  * The **Minimum Euclidean Distance** for finding the closest match between one d-dimensional element and a database of n d-dimensional elements.
  * The [**Arithmetic Inner Product**](https://en.wikipedia.org/wiki/Dot_product#Algebraic_definition) that multiplies N values component-wise and then adds all multiplication results (modulo 16 Bit in this case).
  * Secure Hash Function Evaluation [**SHA1**](https://en.wikipedia.org/wiki/SHA1), where both parties concatenate their 256-bit inputs to a 512-bit message which is collaboratively hashed using SHA1.
  * The LowMC block cipher family [**LowMC**](http://eprint.iacr.org/2016/687), which is a block cipher familiy with a low number of AND gates and a low AND depth. In the example, one party inputs the key and the other party inputs a message to collaboratively encrypt.
  * Further example applications will be added soon.

#### Running Applications
  * Make sure you have called `make` and the application's binary was created in `bin/`.
  * To locally execute an application, run the created executable from **two different terminals** and pass all required parameters accordingly.
  * By default applications are tested locally (via sockets on `localhost`). You can run them on two different machines by specifying IP addresses and ports as parameters.
  * **Example:** The Millionaire's problem requires to specify the role of the executing party. All other parameters will use default values if they are not set. You execute it locally with: `./millionaire_prob.exe -r 0` and `./millionaire_prob.exe -r 1`, each in a separate terminal.
  * You should get some debug output for you to verify the correctness of the computation.
  * Performance statistics can be turned on setting `#define PRINT_PERFORMANCE_STATS 1` in `src/abycore/ABY_utils/ABYconstants.h` in [line 32](https://github.com/encryptogroup/ABY/blob/public/src/abycore/ABY_utils/ABYconstants.h#L32).

#### Creating and Building your own ABY Application
  * Create a copy of the folder `millionaire_prob` inside the `examples/` directory and give it a meaningful name, e.g. `my_application`:
```bash
cd src/examples/
cp -r millionaire_prob/ my_application/
```
  * We now work in this newly created folder, e.g. `cd my_application/`.
  * You can rename the file names inside your folder, just make sure to reference them correctly within each other. The included `Makefile` is generic and should be left unchanged.
  * Follow the comments in the included `.cpp` files to get an idea how to create an ABY example.
  * The `common/` directory should contain a description of the circuit (its functionality) and ideally a function to test this circuit. The root `.cpp` should contain a `main()` method that calls this test function and passes the correct parameters.
  * When ready to build, simply execute `make` in your example's directory *or* in the ABY root directory.
  * On successful build an executable with the name `my_application.exe` is created in `bin/` (this depends on the directory name you chose).
