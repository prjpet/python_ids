#!/usr/bin/python3.5
import os, sys
from utils import MyParser
from sniffer import Sniffer
from io_parser import IOParser

if __name__ == '__main__':
    # Create argparser object to add command line args and help option
    parser = MyParser(
    	description = 'This Python script sniffs the interface given to it using the pyshark module.',
    	epilog = '',
    	add_help = True)

    # Add a "-i" argument to receive a filename
    parser.add_argument("-i", action = "store", dest="interface",
    					help = "Interface to Sniff?")

    # Print help if no args are supplied
    if len(sys.argv)==1:
    	parser.print_help()
    	sys.exit(1)

    args = parser.parse_args()

    #1. Parse IO list

    parser = IOParser()
    try:
        parser.parseList("/sne/home/pprjevara/Documents/rp1/virtuaplant/documentation/modbus_io_list.csv")
        device_list = parser.generateDataStructure()
    except Exception as e:
        print(e)

    print(device_list)
    #2. Start learning phase - learn valid states and the sequence

    #mySniffer = Sniffer(args.interface)
    #mySniffer.startSniffing()
