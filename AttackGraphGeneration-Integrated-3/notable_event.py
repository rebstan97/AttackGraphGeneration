from event import Event
from input_parser import Parser

class NotableEvent(object):        

    # returns the immediate previous state node
    def parseNotableEvent(self, stateNode):
        parser = Parser()
        vulnerabilitySet = Parser.parseVulnerabilities(stateNode)
        # checks all associated events that can come from the specific state node's vulnerabilities
        for vulnerabilityNode in vulnerabilitySet:
            event = self.parseVulnerabilityToEvent(vulnerabilityNode))
            if self.isEventPresent(eventSet) != false:
                previousStateNode = self.isEventPresent(eventSet)
                return (vulnerabilityNode, previousStateNode)
            else:
                return (vulnerabilityNode, None)

    # returns the event description of the vulnerability
    def parseVulnerabilityToEvent(self, vulnerabilityNode):
        try:
            with open("datastructure.csv") as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',')
                for row in csv_reader:
                    if vulnerabilityNode.vulnerabilityName == row[0]:
                        eventDescription = row[1]
                        event = Event(eventDescription)                            
                        return event

    # returns previous state node's hostname that matches an event in recorded eventset
    def isEventPresent(self, eventSet):
        try:
            with open("eventset.csv") as csv_file:
                data = csv.DictReader(csvfile)
                for row in data:
                    for event in eventSet:
                        if event.description == row[5]:
                            hostname = row[1]
                            accessLevel = row[2]
                            previousStateNode = StateNode(hostname, accessLevel)
                            return previousStateNode
                
            return false
