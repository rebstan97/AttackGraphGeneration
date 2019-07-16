class StateNode(object):
    def __init__(self, hostname, accessLevel):
        self.hostname = hostname
        self.accessLevel = accessLevel

    def to_string(self):
        return "({}, {})".format(self.hostname, self.accessLevel)

    def __eq__(self, other):
        return self.hostname == other.hostname and self.accessLevel == other.accessLevel

    def __hash__(self):
        return hash(('hostname', self.hostname, 'accessLevel', self.accessLevel))
