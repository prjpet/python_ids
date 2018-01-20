#!/usr/bin/python3.5
import pyshark, os, sys, time
from utils import MyParser

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

    capture = pyshark.LiveCapture(interface=args.interface)

    UPPER_LAYER = 'mbtcp'
    LOWER_LAYER = 'modbus'

    UPPER_LAYER_SIGNATURE = "<"+UPPER_LAYER+">"
    LOWER_LAYER_SIGNATURE = "<"+UPPER_LAYER+">"

    holding_reg_range = 0
    trans_id = 0
    funct_code = 0
    prev_trans_id = 0
    prev_func_code = 0

    for packet in capture.sniff_continuously():

        #check if the packet has the required protocol to sniff!
        #THIS IS TO BE CORRECTED, to take s7comm as well!!!

        #https://www.wireshark.org/docs/dfref/s/s7comm.html
        #https://www.wireshark.org/docs/dfref/m/mbtcp.html
        #https://osqa-ask.wireshark.org/questions/50063/getting-register-values-from-modbustcp-response

        if UPPER_LAYER in packet:
            #Since we know that the system is using modbus
            #From the IO list we can also retrieve what registers are we reading
            #BUT WE CAN GET BOTH OF THE VALUES WITH CERTAINTY:
            #    - trans_id: this is a unique id for each write / request, which for response have to be received
            #                every trans_id is for a pair of messages - an initial message and a response
            #    - func_code: the function code of the modbus function
            #    - word_cnt: when reading registers

            trans_id = packet[UPPER_LAYER].trans_id
            func_code = packet[LOWER_LAYER].func_code
            command_response = ""

            #print("ID: ", trans_id, "FC: ", func_code)
            #if this is the same transaction as before, it's a responsible else it's a command
            if trans_id == prev_trans_id and func_code == prev_func_code: command_response = "Res - "
            else: command_response = "Com - "

            #to avoid errors, verify whether the packet has the required attribute
            if hasattr(packet[LOWER_LAYER], 'data'):
                print(command_response, "Write data: ", packet[LOWER_LAYER].data, ", to address: ", packet[LOWER_LAYER].reference_num)

            #to avoid errors, verify whether the packet has the required attribute
            elif hasattr(packet[LOWER_LAYER], 'word_cnt'):
                reading_from  = int(packet[LOWER_LAYER].reference_num)
                holding_reg_range = int(packet[LOWER_LAYER].word_cnt)
                print(command_response, "Reading data from register ", reading_from, ", " , holding_reg_range, " registers:")

            #to avoid errors, verify whether the packet has the required attribute
            elif hasattr(packet[LOWER_LAYER], 'reg16'):
                print(command_response, "Reading data from ", holding_reg_range, " registers.")
                #In theory, the above extracted word_cnt can be used to set the for
                for i in range (0, holding_reg_range):
                    print(packet[LOWER_LAYER].reg16.all_fields[i].showname_key,": ", packet[LOWER_LAYER].reg16.all_fields[i].showname_value )

            prev_trans_id = trans_id
            prev_func_code = func_code
            #print(packet[4])
            #DISPLAY CONTENTS
            #an = packet[
            #attrs = vars(an)
            # {'kids': 0, 'name': 'Dog', 'color': 'Spotted', 'age': 10, 'legs': 2, 'smell': 'Alot'}
            # now dump this in some way or another
            #print(', '.join("%s: %s" % item for item in attrs.items() ) )
