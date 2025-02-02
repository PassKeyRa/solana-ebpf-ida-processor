import sys
import pathlib

from idaapi import *

# Add the path to the IDA procs directory to the sys.path
ida_procs_dir = pathlib.Path(__file__).parent.parent / 'procs'
sys.path.append(str(ida_procs_dir))

from solana.processor import EBPFProc

def PROCESSOR_ENTRY():
    return EBPFProc()
