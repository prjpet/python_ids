import pyshark, os, sys, time
from utils import MyParser

class Dissector:
    def __init__(self, iface="lo", protocols=["modbus"]):
        """ protocols = list that contains the required protocols
            interface = interface to sniff """

        self.packet = None
        #self.protocols = protocols
        #self.setProtocolVariables()


    def __str__(self):
        """ everybody likes printable objects right?
            later might be useful for error handling """

        return "<Protocols and layers: {0}>".format(self.protocolLayers)


    def dissectModbus(self, packet, protocolAttributes):
        """ if the protocol is found in the packet, dissect the packet based on modbus characteristics """
        #Since we know that the system is using modbus
        #From the IO list we can also retrieve what registers are we reading
        #    - trans_id: this is a unique id for each write / request, which for response have to be received
        #                every trans_id is for a pair of messages - an initial message and a response
        #    - func_code: the function code of the modbus function
        #    - word_cnt: how many registers

        #Since devices are organised by address in the device_list dictionary, the following can be done:
        #    - if message to an address is caught that is not in the list, raise alarm and note address and value
        #            - potentially BLOCK the message if allowed (sniffer placed on link between HMI and device)
        #    - if message to a known address is caught AND in learning phase, save the state
        #            - compare the state by hashing
        #    - BUILD SEQUENCE DIAGRAM from learned states using the state object
        #            - the learning state should work independently from the IO list
        #            - device tag - state
        #            - write to xml or csv
        #            - when in ENFORCEMENT, parse csv and use that, this way the system is not a black box
        #    - if in the enforcement phase, register good messages counter

        required_layer = packet["modbus"]

        protocolAttributes["modbus"]["trans_id"] = packet["mbtcp"].trans_id
        protocolAttributes["modbus"]["func_code"] = required_layer.func_code
        command = True

        #print("ID: ", trans_id, "FC: ", func_code)
        #if this is the same transaction as before, it's a responsible else it's a command
        if protocolAttributes["modbus"]["trans_id"] == protocolAttributes["modbus"]["prev_trans_id"] and protocolAttributes["modbus"]["func_code"] == protocolAttributes["modbus"]["prev_func_code"]: command = True
        else: command = False

        #to avoid errors, verify whether the packet has the required attribute
        if hasattr(required_layer, 'data'):
            #writing is happening
            print(command, "Write data: ", required_layer.data, ", to address: ", required_layer.reference_num)
            

        #to avoid errors, verify whether the packet has the required attribute
        elif hasattr(required_layer, 'word_cnt'):
            #request for reading_multiple_registers is happening
            protocolAttributes["modbus"]["reading_from"]  = int(required_layer.reference_num)
            protocolAttributes["modbus"]["holding_reg_range"] = int(required_layer.word_cnt)
            print(command, "Reading data from register ", protocolAttributes["modbus"]["reading_from"], ", " , protocolAttributes["modbus"]["holding_reg_range"], " registers:")

        #to avoid errors, verify whether the packet has the required attribute
        elif hasattr(required_layer, 'reg16'):
            print(command, "Reading data from ", protocolAttributes["modbus"]["holding_reg_range"], " registers.")
            #In theory, the above extracted word_cnt can be used to set the for
            for i in range (0, protocolAttributes["modbus"]["holding_reg_range"]):
                print(required_layer.reg16.all_fields[i].showname_key,": ", required_layer.reg16.all_fields[i].showname_value )

        else:
            raise Exception("Fatal Error: No modbus variables can be found.")

        protocolAttributes["modbus"]["prev_trans_id"] = protocolAttributes["modbus"]["trans_id"]
        protocolAttributes["modbus"]["prev_func_code"] = protocolAttributes["modbus"]["func_code"]

    def dissectS7(self):
        raise NotImplementedError(self.__class__.__name__ + '.dissectS7()')
