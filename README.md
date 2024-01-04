# IDA Pro Solana bytecode processor

This is the processor plugin for IDA Pro that adds the ability to analyze Solana Virtual Machine bytecode. Since SVM is based on the enhanced Berkeley Packet Filter (eBPF) and mostly uses the same instruction set, [this](https://github.com/zandi/eBPF_processor) eBPF processor plugin was used as a basis.

## How to use

Copy `ebpf.py` to the directory `<ida pro installation>/procs` and select the processor on a Solana program file loading to IDA.

To dump a program from Solana mainnet use the following command:

```
solana program dump <address of an account> <output file>
```

## TODO

* Fix XREFs for functions parsed from relocations
* Figure out, how to parse relocations without loding the binary again
* Add FLIRT signatures
* Come up with more improvements for better bytecode readability

## Thanks

Thanks to Clément Berthaux (clement (dot) berthaux (at) synacktiv (dot) com) and Michael Zandi (the (dot) zandi (at) gmail (dot) com) for developing the EBPF processor plugin, which is the base for this plugin.