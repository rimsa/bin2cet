# bin2cet

bin2cet is a tool to transform a binary to a compatible one with Intel® CET (Control-Flow Enforcement Technology).

## Building

Clone the bin2cet repository and build the test programs.

    $ git clone https://github.com/rimsa/bin2cet
    $ cd bin2cet/tests
    $ make
    $ cd ..

Install the following prerequisities:

1) LIEF: Library to Instrument Executable Formats (https://lief.re/)

        $ cd contrib
        $ python3 -m venv bin2cet
        $ bin2cet/bin/pip3 install --upgrade pip
        $ bin2cet/bin/pip3 install lief==0.17.6
        $ cd ..

2) e9patch (https://github.com/GJDuck/e9patch)

        $ sudo apt install -y markdown
        $ cd contrib
        $ git clone https://github.com/GJDuck/e9patch.git
        $ cd e9patch
        $ patch -p1 < ../../e9reloc.patch
        $ patch -p1 < ../../e9cet.patch
        $ ./build.sh
        $ cd ../..

3) ghidra (https://github.com/nationalsecurityagency/ghidra)

        $ cd contrib
        $ wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip
        $ unzip ghidra_11.0.3_PUBLIC_20240410.zip
        $ rm ghidra_11.0.3_PUBLIC_20240410.zip
        $ cd ..

## Running

1) First, load the environment to use the auxiliary tools.

        $ source bin2cet.env

2) Then, run ghidra with binanalyzer to extract binary information of the desired program(s).

        $ mkdir ghidra-project
        $ analyzeHeadless ghidra-project analyzer -import ./tests/calc -postScript ./analyzer/binanalyzer.py
        $ analyzeHeadless ghidra-project analyzer -import ./tests/figures -postScript ./analyzer/binanalyzer.py
        $ rm -rf ghidra-project

3) Finally, patch the binary to make it CET compatible.

        $ python3 bin2cet.py --keep --verbose tests/calc tests/calc.json tests/calc.patched
        $ ./tests/calc.patched 7 '*' 3

        $ python3 bin2cet.py --keep --verbose tests/figures tests/figures.json tests/figures.patched
        $ ./tests/figures.patched 4 5 'rectangle'

## Troubleshooting

If python is unable to execute the ```match``` command, it is because of your python version is too old. Please use python >= 3.10.

        $ python3 bin2cet.py ...
          File "bin2cet.py", line 137
            match patch['patch_type']:
                  ^

        SyntaxError: invalid syntax

bin2cet supports patching only function entries or indirect jumps. If you want to patch only function entries, use the ```--strategies target_address```. Use ```--help``` for other options.

        $ python3 bin2cet.py --strategies target_address ...
