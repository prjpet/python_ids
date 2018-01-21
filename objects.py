class ModbusObject:
    """ a modbus object has the following properties:
    address, digital, current_state, valid_states, tag_name """

    def __init__(self,tag_name="modbus_object", address = 0, digital = True):
        """  """
        self.tag_name = tag_name
        self.address = address
        self.current_state = State()
        self.valid_states = []
        self.digital = digital

    def __str__(self):
        """ everybody likes printable objects right?
        later might be useful for error handling     """

        return "<{0} {1} {2} {3} {4}>".format(\
                self.tag_name,\
                self.address,\
                self.current_state,\
                self.valid_states,\
                self.digital)

class State:
    """ The state of a device, which is address + value"""

    def __init__(self,address = 0, value=0):
        """  """
        self.address = address
        self.value = value


    def __str__(self):
        """ everybody likes printable objects right?
        later might be useful for error handling     """

        return "<{0} {1}>".format(\
                self.address,\
                self.value)
