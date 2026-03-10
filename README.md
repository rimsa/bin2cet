# bin2cet

bin2cet is a tool to transform a binary to a compatible one with Intel® CET (Control-Flow Enforcement Technology).

## Building

Clone the bin2cet repository and build the tests.

    $ git clone https://github.com/rimsa/bin2cet
    $ cd bin2cet/tests
    $ make
    $ cd ..

Install the following prerequisities:

1) LIEF: Library to Instrument Executable Formats (https://lief.re/)

        $ cd contrib
        $ python3 -m venv myenv
        $ export PATH="$(pwd)/myenv:${PATH}"
        $ pip3 install --user lief
        $ cd ..

2) e9patch (https://github.com/GJDuck/e9patch)

        $ sudo apt install -y markdown
        $ cd contrib
        $ git clone https://github.com/GJDuck/e9patch.git
        $ cd e9patch
        $ patch -p1 < ../../reloc.patch
        $ ./build.sh
        $ export PATH="$(pwd):${PATH}"
        $ cd ../..

3) ghidra (https://github.com/nationalsecurityagency/ghidra)

        $ cd contrib
        $ wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip
        $ unzip ghidra_11.0.3_PUBLIC_20240410.zip
        $ rm ghidra_11.0.3_PUBLIC_20240410.zip
        $ export PATH="$(pwd)/ghidra_11.0.3_PUBLIC/support:${PATH}"
        $ cd ..

## Running

1) First, run binanalyzer with ghidra to extract binary information.

        $ mkdir ghidra-project
        $ analyzeHeadless ghidra-project analyzer -import ./tests -postScript ./binanalyzer.py

2) Then, patch the binary to make it CET compatible.

        $ python3 bin2cet.py --keep --verbose tests/calc tests/calc.json tests/calc.patched
        $ ./tests/calc.patched 7 '*' 3

        $ python3 bin2cet.py --keep --verbose tests/figures tests/figures.json tests/figures.patched
        $ ./tests/figures.patched 4 5 'rectangle'
