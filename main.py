#!/usr/bin/python3.5
#dependencies: pyshark, tshark, wireshark

import os, sys, pyshark
from utils import MyParser
from sniffer import Dissector
from io_parser import IOParser

def setProtocolVariables(protocols):
    """ fill a dictionary with the protocol specific parameters
        LAYERS and HANDLERS"""
    protocolLayers = {}
    protocolHandlers = {}
    protocolAttributes = {}

    for protocol in protocols:
        if protocol == "modbus":
            protocolLayers[protocol] = ["mbtcp", "modbus"]
            protocolAttributes[protocol] = {"reading_from":0, "holding_reg_range": 0, "trans_id": 0, "prev_trans_id": 0, "prev_func_code": 0, "funct_code": 0, "prev_trans_id": 0, "prev_func_code": 0}
            #protocolHandlers[protocol] = Dissector.dissectModbus
        elif protocol == "s7":
            protocolLayers[protocol] = ["none", "s7comm"]
            #self.protocolAttributes[protocol] = {holding_reg_range: 0, trans_id: 0, funct_code: 0, prev_trans_id: 0, prev_func_code: 0}
            #protocolHandlers[protocol] = Dissector.dissectS7

    return {"protocolLayers": protocolLayers, "protocolHandlers": protocolHandlers, "protocolAttributes":protocolAttributes}


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
    #try:
    parser.parseList("/sne/home/pprjevara/projects/virtuaplant/documentation/modbus_io_list.csv")
    modbus_device_list = parser.generateDataStructure()

    #all devices lists should be indexed based on the addresses they are using, so when
    #a packet is captured, the respective device can be filtered out easily
    print(modbus_device_list)

    #protocol can also be sniffed but for proof of concept we will just assume modbus only
    protocols = ["modbus"]
    protocolVariables = setProtocolVariables(protocols)
    #2. Start learning phase - learn valid states and the sequence that they follow each other in
    capture = pyshark.LiveCapture(interface=args.interface)
    myDissector = Dissector()

    for packet in capture.sniff_continuously():
        for protocol in protocolVariables["protocolLayers"]:

            if packet.highest_layer.lower() in protocolVariables["protocolLayers"][protocol]:

                    myDissector.dissectModbus(packet, protocolVariables["protocolAttributes"])
