import simplejson as json
import networkx as nx

def save(G, fname):
     json.dump(dict(edges=[u,v for u,v in G.edges()]),
               open(fname, 'w'), indent=2)

def load(fname):
     G = nx.DiGraph()
     d = json.load(open(fname))
     G.add_nodes_from(d['nodes'])
     G.add_edges_from(d['edges'])
     return G