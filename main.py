#!/usr/bin/python3.5
#dependencies: pyshark, tshark, wireshark

import os, sys, pyshark, time
from utils import MyParser
from sniffer import Dissector
from io_parser import IOParser
from objects import SystemState

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

def printDevices(header,devlist):
    print(header)
    for item in devlist:
        print(item)

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
    #print(modbus_modbus_device_list)

    #protocol can also be sniffed but for proof of concept we will just assume modbus only
    protocols = ["modbus"]
    protocolVariables = setProtocolVariables(protocols)
    #2. Start learning phase - learn valid states and the sequence that they follow each other in
    capture = pyshark.LiveCapture(interface=args.interface)
    myDissector = Dissector()

    REQUEST_COUNTER = 0
    RESPONSE_COUNTER = 0
    DROPPED_PACKET_COUNTER = 0
    REQ_RES_MAX_ERROR = 0
    packet_contents = ""
    previous_packet_contents = ""
    request = False

    mode = [[20,],[300,],[0,]]
    mode_index = 0

    mySystemState = SystemState()

    ANOMALY_COUNTER = 0

    printDevices("Parsed devices: ", modbus_device_list)

    #TODO - move this into a separate THREAD using threading or multiprocessing
    for i, packet in enumerate(capture.sniff_continuously()):
        for protocol in protocolVariables["protocolLayers"]:

            #if the highest layer of the packet is in the protocol variables of the current protocol,
            #then we have identified the protocol
            if packet.highest_layer.lower() in protocolVariables["protocolLayers"][protocol]:
                    #first packet
                    #capture time
                    if i == 0:
                        packet_contents = myDissector.dissectModbus(packet)
                        first_packet_time = time.time()
                    else:
                        previous_packet_contents = packet_contents
                        packet_contents = myDissector.dissectModbus(packet)
                        next_packet_time = time.time()

                        #meaning packet is for the same transaction
                        if packet_contents["trans_id"] == previous_packet_contents["trans_id"]:
                            RESPONSE_COUNTER += 1
                            request = False
                        else:
                            REQUEST_COUNTER += 1
                            request = True

                        #if no request is received for a response, increase dropped packet counter and potentially
                        #also increase the time it takes for the particular learning phase to finish

                        #LEARNING PHASE CONTROLLERS
                        if mode_index == 0:
                            #we are in default learning phase if response is received and device is fouind
                            #grab the packet address and if there is a device at the index, register default state
                            #IF NO DEVICE, REGISTER AND SIGNAL ANOMALY
                            if not request:
                                if packet_contents['func_code'] == 3:
                                    #since we know that we now read every device's state with func code 6...
                                    print("********** READING ALL DEVICES DEFAULT WITH FUNCTION CODE 6 - REGISTER DEFAULT. **********")
                                    #go through the contents of the holding registers
                                    for i, device_value in enumerate(packet_contents['contents']):
                                        device_index = i+1
                                        #first register default state for device
                                        if device_index in modbus_device_list:

                                            modbus_device_list[device_index].default_state = device_value

                                            #then add device to the system default state descriptor list
                                            mySystemState.default_state.append(modbus_device_list[device_index])
                                        else:
                                            print("********** ADDRESS NOT FOUND - Please submit revised I/O list. **********")
                                            print(packet_contents)
                                            sys.exit(3)


                            if next_packet_time - first_packet_time > mode[mode_index][0]:
                                mode_index += 1
                                normal_learning_start = time.time()
                                print("********* LEARNING DEFAULTS finished - advancing to LEARNING NORMAL.**********")
                                printDevices("Learned defaults: ", mySystemState.default_state)

                        elif mode_index == 1:
                            #we are in normal learning phase
                            if next_packet_time - normal_learning_start > mode[mode_index][0]:
                                mode_index += 1
                                print("********* LEARNING NORMAL finished - advancing to ENFORCEMENT.**********")


            print(i, packet_contents, RESPONSE_COUNTER, REQUEST_COUNTER)
