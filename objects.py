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

    def __init__(self,address = 0, value=0):
        """  """
        self.address = address
        self.value = value
        self.current_state = {}
        self.defautl_state = {}
        self.valid_states = [{}]


    def __str__(self):
        """ everybody likes printable objects right?
        later might be useful for error handling     """

        return "<{0} {1}>".format(\
                self.address,\
                self.value)

    def initValidStates():
        print(".")
