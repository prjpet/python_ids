class ModbusObject:
    """ a modbus object has the following properties:
    address, digital, current_state, valid_states, tag_name """

    def __init__(self,tag_name="modbus_object", address = 0, current_state = 0, valid_states=[0], digital = True):
        """  """
        self.tag_name = tag_name
        self.address = address
        self.current_state = current_state
        self.valid_states = valid_states3
        self.digital = digital

    def __str__(self):
        """ everybody likes printable objects right?
        later might be useful for error handling

        return "<{0} {1} {2} {3} {4}>".format(\
                self.tag_name = tag_name,\
                self.address = address,\
                self.current_state = current_state,\
                self.valid_states = valid_states,\
                self.digital = digital)
            """
