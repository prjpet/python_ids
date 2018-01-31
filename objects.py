import hashlib, time
class ModbusObject:
    """ a modbus object has the following properties:
    address, digital, current_state, valid_states, tag_name """

    def __init__(self,tag_name="modbus_object", address = 0, digital = True, logical_group = 0, default_state = 0):
        """  """
        self.tag_name = tag_name
        self.address = address
        self.current_state = 0
        self.valid_states = []
        self.digital = digital
        self.logical_group = logical_group
        self.default_state = default_state

    def __str__(self):
        """ everybody likes printable objects right?
        later might be useful for error handling     """

        return "<{0} {1} {2} {3} {4} {5} {6}>".format(\
                self.tag_name,\
                self.address,\
                self.current_state,\
                self.valid_states,\
                self.digital,\
                self.logical_group,\
                self.default_state)


class SystemState:
    """ The state of the system, which is a group of addresses + values
        The size of the group is defined by the number of elements provided as initial setup information"""

    def __init__(self):
        """  """
        self.default_state = 0
        self.next_state = 0
        self.current_state = 0
        self.digital_statechart = { 1:{}, 2:{} }
        self.valid_states = {"all":[], "digital":[], "analogue":[]}


    def __str__(self):
        """ everybody likes printable objects right?
        later might be useful for error handling     """

        return "<{0} {1}>".format(\
                self.address,\
                self.value)

    def buildStatechartFromDefault(self):
        string_to_hash = ""
        for k in self.default_state:
            #create a hashed state descriptor for the digital states for each of the blocks
            #in the following format:
            #self.digital_statechart = { 1:{}, 2:{} }
            #self.digital_statechart = { 1:{"state1": {"successors": [] , "time_delta": [], "prob": []} }, 2:{} }
            if k in self.digital_statechart:

                for mode in self.default_state[k]:
                    for element in self.default_state[k]["digital"]:
                        string_to_hash += str(element)

                self.digital_statechart[k] = { self.hashState(string_to_hash): {"successors": [self.hashState(string_to_hash),] , "time_delta": [1, ], "prob": [1, ]} }

            else:
                self.digital_statechart[k] = {}

                for mode in self.default_state[k]:
                    for element in self.default_state[k][mode]:
                        string_to_hash += str(element)

                self.digital_statechart[k] = { self.hashState(string_to_hash): {"successors": [self.hashState(string_to_hash),] , "time_delta": [1, ], "prob": [1, ]} }

        print(self.digital_statechart)

    def hashState(self, state):
        return hashlib.sha256(state).hexdigest()
