#!/usr/bin/python3.5
#dependencies: pyshark, tshark, wireshark

import os, sys, pyshark, time, hashlib, math
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
            protocolLayers[protocol] = ["modbus"]
            protocolAttributes[protocol] = {"reading_from":0, "holding_reg_range": 0, "trans_id": 0, "prev_trans_id": 0, "prev_func_code": 0, "funct_code": 0, "prev_trans_id": 0, "prev_func_code": 0}
            #protocolHandlers[protocol] = Dissector.dissectModbus
        elif protocol == "s7":
            protocolLayers[protocol] = ["none", "s7comm"]
            #self.protocolAttributes[protocol] = {holding_reg_range: 0, trans_id: 0, funct_code: 0, prev_trans_id: 0, prev_func_code: 0}
            #protocolHandlers[protocol] = Dissector.dissectS7

    return {"protocolLayers": protocolLayers, "protocolHandlers": protocolHandlers, "protocolAttributes":protocolAttributes}

def printDevices(header,devlist):
    print(header)
    for key in devlist:
        print("***",key,"***")
        for item in devlist[key]:
            print("***",item,"***")
            for thing in devlist[key][item]:
                print(str(thing))

def getState(packet_contents,device_list, i):
    func_code = packet_contents["func_code"]
    final_dict = {}
    if i < 60: print("Packet: ", i, "********** READING ALL DEVICES WITH FUNCTION CODE "+str(func_code)+" - REGISTER STATE. **********")
    if func_code == 3:
        #since we know that we now read every device's state with func code 6...
        #go through the contents of the holding registers
        registers = packet_contents['contents']
        device_index = 0
        for device_value in registers:
            device_index = device_index + 1
            #first register default state for device
            if device_index in device_list:
                device_list[device_index].state = device_value
                #then add device to the system default state descriptor list
                if device_list[device_index].logical_group != '': key = int(device_list[device_index].logical_group)
                else: key = 0

                if device_list[device_index].digital:
                    #append digital to group

                    if key in final_dict:

                        final_dict[ key ]["digital"].append( device_list[ device_index ] )

                    else:
                        final_dict[ key ] = {"analogue": [], "digital":[]}
                        final_dict[ key ]["digital"] = [ device_list[ device_index ]  ]
                else:
                    #append analogue to group
                    if key in final_dict:

                        final_dict[ key ]["analogue"].append( device_list[ device_index ] )

                    else:
                        final_dict[ key ] = {"analogue": [], "digital":[]}
                        final_dict[ key ]["analogue"] = [ device_list[ device_index ]  ]
            else:
                print("********** ADDRESS NOT FOUND - Please submit revised I/O list. **********")
                print(packet_contents)
                sys.exit(3)

        return final_dict

if __name__ == '__main__':
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
    capture = pyshark.LiveCapture(interface='lo')
    myDissector = Dissector()

    REQUEST_COUNTER = 0
    RESPONSE_COUNTER = 0
    DROPPED_PACKET_COUNTER = 0
    REQ_RES_MAX_ERROR = 0
    packet_contents = ""
    previous_packet_contents = ""
    request = False

    mode = [[5,],[1200,],[0,]]
    mode_index = 0

    mySystemState = SystemState()

    TRAINING_DATA = {}
    TRAINING_STATE_LIST = []
    LINE_COUNT = 0
    ANOMALY_COUNTER = 0

    #printDevices("Parsed devices: ", modbus_device_list)
    i = -1
    #TODO - move this into a separate THREAD using threading or multiprocessing
    for packet in capture.sniff_continuously():

        #if the highest layer of the packet is in the protocol variables of the current protocol,
        #then we have identified the protocol
        if packet.highest_layer.lower() in protocolVariables["protocolLayers"]["modbus"]:
                i += 1
                #first packet
                #capture time
                #!!!!!_________BASTARD___________!!!!!
                modbus_device_list = parser.generateDataStructure()
                if i == 0:
                    packet_contents = myDissector.dissectModbus(packet)
                    first_packet_time = time.time()
                else:

                    previous_packet_contents = packet_contents
                    packet_contents = myDissector.dissectModbus(packet)
                    next_packet_time = time.time()

                    #meaning packet is for the same transaction
                    #print(packet_contents["trans_id"], previous_packet_contents["trans_id"])
                    if packet_contents["trans_id"] == previous_packet_contents["trans_id"]:
                        RESPONSE_COUNTER += 1
                        request = False
                    else:
                        REQUEST_COUNTER += 1
                        request = True

                    #if no request is received for a response, increase dropped packet counter and potentially
                    #also increase the time it takes for the particular learning phase to finish
                    if not request:
                        #LEARNING PHASE CONTROLLERS
                        if mode_index == 0:

                            #we are in default learning phase if response is received and device is fouind
                            #grab the packet address and if there is a device at the index, register default state
                            #IF NO DEVICE, REGISTER AND SIGNAL ANOMALY
                            #we finished learning time:

                            if next_packet_time - first_packet_time > mode[mode_index][0]:
                                mode_index += 1
                                mySystemState.buildStatechartFromDefault()
                                current_system_state = 0
                                previous_system_state = 0
                                block_time = 0
                                prev_block_time = 0
                                normal_learning_start = time.time()
                            #and mySystemState.next_state[1]["digital"] != mySystemState.state[1]["digital"]: mode_index += 1

                            #we are still in learning phase:
                            #if different states are received, let the operator know that we need to stabilise the system
                            else:
                                #in our test environments case, response to func_code 3 will result in the full state to be pulled
                                if packet_contents["func_code"] == 3:

                                    #the getState can be used to run through contents of response for func_code requests
                                    if mySystemState.state == 0:
                                        mySystemState.state = getState(packet_contents,modbus_device_list, i)
                                        mySystemState.next_state = mySystemState.state
                                    else:
                                        mySystemState.next_state = getState(packet_contents,modbus_device_list, i)

                                #printDevices("Default state: ", mySystemState.state)

                        elif mode_index == 1:

                            #BUILD STATECHART FROM DIGITAL STATES
                            #Build digital only list
                            """
                            ('***', 1, '***')  ----- Layer 1
                            ('***', 'analogue', '***') ----- Layer 2
                            ('***', 'digital', '***') ----- Layer 2
                            <PLC_FEED_PUMP_COM 1 0 [] True 1 0> ----- Layer 3
                            <PLC_TANK1_LEVEL 2 0 [] True 1 0>
                            <PLC_OUTLET_VALVE 3 0 [] True 1 0>
                            """

                            """
                            {0: {'fa7b6d0b65ffcc51b7dd50ad141e6ecb0daca0987a8086b21d3ee084c72ff215': {'successors': [], 'prob': [], 'time_delta': []}},
                            1: {'b29d59cb44b514b724f07cdd2a0e229416c84065e9fb9b2f9a6df5f1e03e3302': {'successors': [], 'prob': [], 'time_delta': []}},
                            2: {'7a31010015e85572fe16d581f18bf79e0fd967a12717a1ca601fddcef914ecb2': {'successors': [], 'prob': [], 'time_delta': []}}}
                            """

                            if packet_contents["func_code"] == 3:
                                if current_system_state == 0: print("********* LEARNING DEFAULTS FINISHED - HASHING DIGITAL STATE.**********")

                                current_system_state = getState(packet_contents,modbus_device_list, i)
                                current_time = time.time()
                                #see if there is state change

                                block_to_hash = ''
                                prev_block_to_hash = ''
                                for logical_block in current_system_state:

                                    #roll through the items within the digital block and add to a string
                                    for l, item in enumerate(current_system_state[logical_block]["digital"]):
                                        block_to_hash += str(item)
                                        if previous_system_state != 0: prev_block_to_hash += str(previous_system_state[logical_block]["digital"][l])

                                    #add this state to the current digital state descriptor then compare with statechart basis...
                                    #if not found in statechart and we are in still thelearning phase, register successor, time delta and prob (which is index++/learning time total)
                                    hashed_block = mySystemState.hashState(block_to_hash)
                                    block_time = time.time()
                                    if previous_system_state != 0:
                                        prev_hashed_block = mySystemState.hashState(prev_block_to_hash)

                                    #Have we seen this state before?
                                    if hashed_block in mySystemState.digital_statechart[logical_block]:

                                        if hashed_block in mySystemState.digital_statechart[logical_block][hashed_block]["successors"]:
                                            #increase probability
                                            item_index = mySystemState.digital_statechart[logical_block][hashed_block]["successors"].index(hashed_block)
                                            mySystemState.digital_statechart[logical_block][hashed_block]["prob"][item_index] += 1

                                    else:
                                        mySystemState.digital_statechart[logical_block][hashed_block] = {"successors": [hashed_block,] , "time_delta": [1, ], "prob": [1, ]}

                                    #if we have registered a state previously, then we can measure Td between new state and previous
                                    #in order to build training model, need to grab these values, alongside with the block's analogue values
                                    #store them in a list each with the same index
                                    #the result should be 1 timestamped list / logical block of:
                                    #    - timestamp
                                    #    - Td for current state change
                                    #    - analogue values as described in block
                                    #Feed all this into LSTM, getting predictions for Td
                                    #Also feed analogue values into LSTM asking for predictions for Analogue values
                                    if previous_system_state != 0:
                                        current_time_delta = block_time - prev_block_time
                                        if hashed_block not in mySystemState.digital_statechart[logical_block][prev_hashed_block]["successors"]:
                                            mySystemState.digital_statechart[logical_block][prev_hashed_block]["successors"].append(hashed_block)
                                            mySystemState.digital_statechart[logical_block][prev_hashed_block]["time_delta"].append(current_time_delta)
                                            mySystemState.digital_statechart[logical_block][prev_hashed_block]["prob"].append(1)
                                        else:
                                            item_index = mySystemState.digital_statechart[logical_block][prev_hashed_block]["successors"].index(hashed_block)
                                            mySystemState.digital_statechart[logical_block][prev_hashed_block]["prob"][item_index] += 1
                                            mySystemState.digital_statechart[logical_block][prev_hashed_block]["time_delta"][item_index] = current_time_delta

                                        training_line = []
                                        LINE_COUNT += 1
                                        if logical_block == 2:
                                            print(mySystemState.digital_statechart[logical_block])
                                            print(str(prev_hashed_block) + str(hashed_block))
                                            current_transition = str(prev_hashed_block) + str(hashed_block)
                                            if current_transition not in TRAINING_STATE_LIST:
                                                TRAINING_STATE_LIST.append(current_transition)


                                            training_line.append(str(LINE_COUNT))
                                            training_line.append(str(TRAINING_STATE_LIST.index(current_transition)))
                                            training_line.append(str(round(current_time_delta, 3)))
                                            for analogue_device in current_system_state[logical_block]["analogue"]:
                                                training_line.append(str(analogue_device.state))

                                            if logical_block in TRAINING_DATA:
                                                TRAINING_DATA[logical_block].append(training_line)
                                            else:
                                                TRAINING_DATA[logical_block] = [training_line]
                                            with open('test_data'+str(logical_block)+'.txt', 'a') as the_file:
                                                print(', '.join(training_line))
                                                the_file.write(', '.join(training_line))






                                #print(mySystemState.digital_statechart)

                                previous_system_state = current_system_state
                                prev_block_time = block_time


                                current_system_state = None
                                current_time = None
                                #we are in normal learning phase
                                if next_packet_time - normal_learning_start > mode[mode_index][0]:
                                    mode_index += 1
                                    print("********* LEARNING NORMAL finished - advancing to MODEL TRAINING. **********")
