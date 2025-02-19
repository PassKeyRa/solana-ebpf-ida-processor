# IDA Pro Solana bytecode processor

This is the processor plugin for IDA Pro that adds the ability to analyze Solana Virtual Machine bytecode. Since SVM is based on the enhanced Berkeley Packet Filter (eBPF) and mostly uses the same instruction set, [this](https://github.com/zandi/eBPF_processor) eBPF processor plugin was used as a basis.

## How to use

Install `requirements.txt`. Copy `solana-init.py` script and the `solana` folder to the directory `<ida pro installation>/procs` and select the processor on a Solana program file loading to IDA.

To dump a program from Solana mainnet use the following command:

```
solana program dump <address of an account> <output file>
```

During the file import into IDA you may encounter the following error:

![](./img/1.png)

This is because the Solana EBPF processor should be selected explicitly. Double-click on the processor name in the processor list and select it:

![](./img/2.png)

Then select Yes:

![](./img/3.png)


## FLIRT signatures

Proceed to the [solana-ida-signatures-factory](https://github.com/PassKeyRa/solana-ida-signatures-factory) repository to generate function signatures.

## What works now

* Solana eBPF instructions disassembling, including function calls and jumps
* Strings detection
* Relocations detection
* FLAIR preprocessor to generate PAT files with libs functions signatures

## TODO

* Parse and name Anchor functions and structures

## Thanks

Thanks to Clément Berthaux (clement (dot) berthaux (at) synacktiv (dot) com) and Michael Zandi (the (dot) zandi (at) gmail (dot) com) for developing the EBPF processor plugin, which is the base for this plugin.