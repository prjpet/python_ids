import pyshark, os, sys, time
from utils import MyParser

class Dissector:
    def __init__(self, iface="lo", protocols=["modbus"]):
        """ protocols = list that contains the required protocols
            interface = interface to sniff """

        self.packet = None
        #self.protocols = protocols
        #self.setProtocolVariables()
        self.readRange = 0
        self.readingFrom = 0
        self.data = ''

    def __str__(self):
        """ everybody likes printable objects right?
            later might be useful for error handling """

        return "<Protocols and layers: {0}>".format(self.protocolLayers)


    def dissectModbus(self, packet):
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
        #to avoid errors, verify whether the packet has the required attribute
        if hasattr(required_layer, 'data'):
            #print(command_response, "Write data: ", required_layer.data, ", to address: ", required_layer.reference_num)
            #data is received in hex format, with a colon separating each byte - so take the colon first...
            #then next line, convert the data to int from hex int
            self.data = required_layer.data.replace(":","")
            return {"func_code": int(required_layer.func_code), "trans_id": int(packet["mbtcp"].trans_id), "address": int(required_layer.reference_num), "data": int(self.data, 16)}
        #to avoid errors, verify whether the packet has the required attribute
        elif hasattr(required_layer, 'word_cnt'):
            self.readingFrom = int(required_layer.reference_num)
            self.readRange = int(required_layer.word_cnt)
            #print(command_response, "Reading data from register ", protocolAttributes["modbus"]["reading_from"], ", " , protocolAttributes["modbus"]["holding_reg_range"], " registers:")
            return {"func_code": int(required_layer.func_code), "trans_id": int(packet["mbtcp"].trans_id), "address": self.readingFrom, "range": self.readRange}
        #to avoid errors, verify whether the packet has the required attribute
        elif hasattr(required_layer, 'reg16'):
            contents = []
            #print(command_response, "Reading data from ", protocolAttributes["modbus"]["holding_reg_range"], " registers.")
            #In theory, the above extracted word_cnt can be used to set the for
            for i in range (0, self.readRange):
                #print(required_layer.reg16.all_fields[i].showname_key,": ", required_layer.reg16.all_fields[i].showname_value )
                contents.append(int(required_layer.reg16.all_fields[i].showname_value))
            return {"func_code": int(required_layer.func_code), "trans_id": int(packet["mbtcp"].trans_id), "address":  self.readingFrom, "range": self.readRange, "contents": contents}
        else:
            raise Exception("Fatal Error: No modbus variables can be found.")

    def dissectS7(self):
        raise NotImplementedError(self.__class__.__name__ + '.dissectS7()')
