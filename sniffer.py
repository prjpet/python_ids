#!/usr/bin/python
import pyshark, argparse, os, sys, time

# Argument Parsing
class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)

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


if __name__ == '__main__':
    i = 0

    UPPER_LAYER = 'mbtcp'
    LOWER_LAYER = 'modbus'

    holding_reg_range = 0

    for packet in capture.sniff_continuously():

        if len(packet.layers) > 4:
            #Since we know that the system is using modbus
            #From the IO list we can also retrieve what registers are we reading
            #BUT WE CAN GET BOTH OF THE VALUES WITH CERTAINTY:
            #    - trans_id: this is a unique id for each write / request, which for response have to be received
            #                every trans_id is for a pair of messages - an initial message and a response
            #    - func_code: the function code of the modbus function
            print("ID: ", packet[UPPER_LAYER].trans_id, "FC: ", packet[LOWER_LAYER].func_code)
            if hasattr(packet[LOWER_LAYER], 'data'):
                print("Data: ", packet['modbus'].data )

            elif hasattr(packet[LOWER_LAYER], 'word_cnt'):

                holding_reg_range = int(packet['modbus'].word_cnt)
                print("Word Count: ",  holding_reg_range)

            elif hasattr(packet[LOWER_LAYER], 'reg16'):
                print("Registers can be found.")
                #In theory, the above extracted word_cnt can be used to set the for
                for i in range (0, holding_reg_range):
                    print(packet['modbus'].reg16.all_fields[i].showname_key,": ", packet['modbus'].reg16.all_fields[i].showname_value )

            #print(packet[4])
            #DISPLAY CONTENTS
            #an = packet[
            #attrs = vars(an)
            # {'kids': 0, 'name': 'Dog', 'color': 'Spotted', 'age': 10, 'legs': 2, 'smell': 'Alot'}
            # now dump this in some way or another
            #print(', '.join("%s: %s" % item for item in attrs.items() ) )
