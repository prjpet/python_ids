import os, sys, csv
from objects import ModbusObject

class IOParser:
    """ Parse the IO list and convert it to Devices and States used int the IDS """

    def __init__(self, min_column_headers=("protocol","io_type", "tag_name", "address")):
        """ path to IO list: Has to be in CSV format.
            column headers: To know what to expect """

        self.min_column_headers = min_column_headers
        self.file_content = []

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

    def identifyProtocols(self):
        """ create a list of protocols from the parsed IO list
            SINCE we have verified that the correct columns are present"""
        #the index is identified where the word protocol is found
        indexOfProtocols = self.file_content[0].index("protocol")

        currentProtocol = "none"
        listOfProtocols = []
        #since the first row contains labels, start from the second
        for row in self.file_content[1:]:
            currentProtocol = row[indexOfProtocols].lower()

            if not currentProtocol in listOfProtocols:
                listOfProtocols.append(currentProtocol)

        print(listOfProtocols)


    def generateDataStructure(self):
        """ when called, creates the devices that are reachable through the differnet protocols,
            based on the IO list """
