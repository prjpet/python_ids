import os, sys, csv
from objects import ModbusObject

class IOParser:
    """ Parse the IO list and convert it to Devices and States used int the IDS """

    def __init__(self, min_column_headers=["protocol","i/o type", "tag name", "address", "logical group"]):
        """ path to IO list: Has to be in CSV format.
            column headers: To know what to expect """

        self.min_column_headers = min_column_headers
        self.file_content = []
        self.indices = {}

        for item in min_column_headers:
            self.indices[item] = 0

    def __str__(self):
        """ everybody likes printable objects right?
            later might be useful for error handling """

        return "<Given Path: {0}, Minimum Tags Required: {1}>".format(\
                self.path_to_file,\
                self.min_column_headers)

    def fatalError(self, type, arg):
        """ Possible errors and return values and respective output messages:

            Error type 1: Invalid Arguments
            Error type 2: Lack of root priviliges for user
            Error type 3: Config arugment not a file
            Error type 4: Config format incorrect
            """

        possibleErrors = ["Invalid arguments. Usage : " + str(arg) + " <create|start|stop|destroy|status|map> <config file>", \
		                  "You need to have root privileges to run this command.\nPlease try again, this time using 'sudo'. Exiting.",\
		                  "IO List given is not a file: " + str(arg),\
                          "Missing columns: " + self]

        return "ERROR  " + possibleErrors[type]

    def verifyCorrectColumnsPresent(self, columns_to_compare):
        """ responsible for verifying if all the required columns are present in
            self.min_column_headers"""

        if len(self.min_column_headers) < len(columns_to_compare):
            #silly test to simulate purpose
            return False
        else:
            return True

    def parseList(self, path_to_file = ""):
        """ parse the IO list, given to the class """
        newlist = []
        if os.path.isfile(path_to_file):

            with open(path_to_file) as csv_file:

                dialect = csv.Sniffer().sniff(csv_file.read(1024))
                csv_file.seek(0)
                reader = csv.reader(csv_file, dialect)

                for i, row in enumerate(reader):
                    if i == 0:
                        #go through all the elements of the first row and make lowercase
                        for item in row:
                            newlist.append(item.lower())
                        self.file_content += [newlist]
                    else:
                        self.file_content += [row]
                csv_file.close()


        else:
            raise Exception("Path to I/O file incorrect.")

        self.fillIndices()
        self.identifyProtocols()

    def fillIndices(self):
        """ store the index of the different columns for the min_column_headers """
        #fill up list of indices
        for item in self.min_column_headers:
            self.indices[item] = self.file_content[0].index(item)


    def identifyProtocols(self):
        """ create a list of protocols from the parsed IO list
            SINCE we have verified that the correct columns are present"""
        #the index is identified where the word protocol is found

        currentProtocol = "none"
        listOfProtocols = []
        #since the first row contains labels, start from the second
        for row in self.file_content[1:]:
            currentProtocol = row[self.indices["protocol"]].lower()

            if not currentProtocol in listOfProtocols:
                listOfProtocols.append(currentProtocol)

        self.listOfProtocols = listOfProtocols


    def generateDataStructure(self):
        """ when called, creates the devices that are reachable through the differnet protocols,
            based on the IO list
            Devices are indexed by their address within the list for now for faster retrieval
            The type of it might change to dictionary, and organised by protocol if necessary"""
        device_data = {}
        #in the io list each line is an object
        #except the first one
        for row in self.file_content[1:]:

            #print(row[ self.indices["tag name"] ], row[ self.indices["address"] ], self.digital( row[ self.indices["i/o type"] ]))
            #print(row[ self.indices["tag name"] ], row[ self.indices["address"] ], self.digital( row[ self.indices["i/o type"] ]))
            new_device = ModbusObject( row[ self.indices["tag name"] ], row[ self.indices["address"] ], self.digital( row[ self.indices["i/o type"] ] ), row[ self.indices["logical group"] ] )

            device_data[ int(row[ self.indices["address"] ]) ] = new_device
        return device_data

    def digital(self, iotype):
        if iotype[0].lower() == "d":
            return True
        else:
            return False
