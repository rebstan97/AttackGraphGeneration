# returns a list of reachable nodes

class Reachable(object):
    def __init__(self):
        # Adjacency list representation
        self.graph = {
            'A': [ ("A", 1521), ("B", 1521), ("C", 80), ("D", 53), ("D", 80)],
            'B': [ ("A", 1521), ("B", 1521), ("C", 80)],
            'C': [ ("A", 1521), ("B", 1521), ("C", 80), ("E", 80)],
            'D': [ ("D", 53), ("D", 80), ("D", 1521), ("E", 80), ("F", 1521)],
            'E': [ ("D", 53), ("D", 80), ("D", 1521), ("E", 80), ("F", 1521)],
            'F': [ ("D", 53), ("D", 80), ("D", 1521), ("E", 80), ("F", 1521)]
        }

    def get_reachable(self, host):
        return self.graph[host]
