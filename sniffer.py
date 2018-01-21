import pyshark, os, sys, time
from utils import MyParser

class Sniffer:
    def __init__(self, iface="lo", protocols=["modbus"]):
        """ protocols = list that contains the required protocols
            interface = interface to sniff """

        self.capture = pyshark.LiveCapture(interface=iface)
        self.packet = None
        self.protocols = protocols
        self.setProtocolVariables()


    def __str__(self):
        """ everybody likes printable objects right?
            later might be useful for error handling """

        return "<Protocols and layers: {0}>".format(self.protocolLayers)

    def startSniffing(self):
        """ based on the initialised information, starts sniffing for specific packets
            The engineer can do the following: """


        for packet in self.capture.sniff_continuously():
            # a single packet can only be either of the protocols - check that and set layer variables based on that
            #check if the packet has the required protocol to sniff!
            #THIS IS TO BE CORRECTED, to take s7comm as well!!!

            #https://www.wireshark.org/docs/dfref/s/s7comm.html
            #https://www.wireshark.org/docs/dfref/m/mbtcp.html
            #https://osqa-ask.wireshark.org/questions/50063/getting-register-values-from-modbustcp-response
            #print(packet._packet_string)
            #check whether packet protocol (defined in the highes layer) is in the ones that need to be sniffed
            for protocol in self.protocolLayers:
                if packet.highest_layer.lower() in self.protocolLayers[protocol]:
                    self.packet = packet
                    self.protocolHandlers[protocol]()



    def dissectModbus(self):
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

        required_layer = self.packet["modbus"]

        self.protocolAttributes["modbus"]["trans_id"] = self.packet["mbtcp"].trans_id
        self.protocolAttributes["modbus"]["func_code"] = required_layer.func_code
        command_response = ""

        #print("ID: ", trans_id, "FC: ", func_code)
        #if this is the same transaction as before, it's a responsible else it's a command
        if self.protocolAttributes["modbus"]["trans_id"] == self.protocolAttributes["modbus"]["prev_trans_id"] and self.protocolAttributes["modbus"]["func_code"] == self.protocolAttributes["modbus"]["prev_func_code"]: command_response = "Res - "
        else: command_response = "Com - "

        #to avoid errors, verify whether the packet has the required attribute
        if hasattr(required_layer, 'data'):
            print(command_response, "Write data: ", required_layer.data, ", to address: ", required_layer.reference_num)

        #to avoid errors, verify whether the packet has the required attribute
        elif hasattr(required_layer, 'word_cnt'):
            self.protocolAttributes["modbus"]["reading_from"]  = int(required_layer.reference_num)
            self.protocolAttributes["modbus"]["holding_reg_range"] = int(required_layer.word_cnt)
            print(command_response, "Reading data from register ", self.protocolAttributes["modbus"]["reading_from"], ", " , self.protocolAttributes["modbus"]["holding_reg_range"], " registers:")

        #to avoid errors, verify whether the packet has the required attribute
        elif hasattr(required_layer, 'reg16'):
            print(command_response, "Reading data from ", self.protocolAttributes["modbus"]["holding_reg_range"], " registers.")
            #In theory, the above extracted word_cnt can be used to set the for
            for i in range (0, self.protocolAttributes["modbus"]["holding_reg_range"]):
                print(required_layer.reg16.all_fields[i].showname_key,": ", required_layer.reg16.all_fields[i].showname_value )

        else:
            raise Exception("Fatal Error: No modbus variables can be found.")

        self.protocolAttributes["modbus"]["prev_trans_id"] = self.protocolAttributes["modbus"]["trans_id"]
        self.protocolAttributes["modbus"]["prev_func_code"] = self.protocolAttributes["modbus"]["func_code"]

    def dissectS7(self):
        raise NotImplementedError(self.__class__.__name__ + '.dissectS7()')

    def setProtocolVariables(self):
        """ fill a dictionary with the protocol specific parameters
            LAYERS and HANDLERS"""
        self.protocolLayers = {}
        self.protocolHandlers = {}
        self.protocolAttributes = {}

        for protocol in self.protocols:
            if protocol == "modbus":
                self.protocolLayers[protocol] = ["mbtcp", "modbus"]
                self.protocolAttributes[protocol] = {"reading_from":0, "holding_reg_range": 0, "trans_id": 0, "prev_trans_id": 0, "prev_func_code": 0, "funct_code": 0, "prev_trans_id": 0, "prev_func_code": 0}
                self.protocolHandlers[protocol] = self.dissectModbus
            elif protocol == "s7":
                self.protocolLayers[protocol] = ["none", "s7comm"]
                #self.protocolAttributes[protocol] = {holding_reg_range: 0, trans_id: 0, funct_code: 0, prev_trans_id: 0, prev_func_code: 0}
                self.protocolHandlers[protocol] = self.dissectS7
