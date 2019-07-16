from graph_generator import GraphGenerator
from input_parser import Parser

parser = Parser()
startNodeSet = parser.parseStartNodes()
vulnDict, portDict = parser.parseVulnerabilities()

graphGenerator = GraphGenerator(startNodeSet, vulnDict, portDict)
DG = graphGenerator.generate_graph()
