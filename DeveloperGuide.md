# Developer Guide
This page documents the solution architecture and algorithms used in the project. The project solution is inspired by an [academic paper](http://people.cs.ksu.edu/~halmohri/files/Practical%20Attack%20Graph%20Generation%20for%20Network%20Defense.pdf) written by K. Ingols, R. Lippmann and K. Piwowarski. 

## Solution Architecture

### Attack Graph Generation
An attack graph (as referred to in this project) comprises of:
* State node: A host in the network + the access level an attacker has on that host
* Vulnerability node: A known CVE
* Edge from a Vulnerability node to a State node if: 
    * The host of the state node has that known CVE
    * Exploiting that vulnerability results in the attacker having the access level of the state node on that host
* Edge from a State node to Vulnerability node if:
    * The host of the state node can reach the host and port containing the vulnerability
    * The attacker's current access level is sufficient to exploit the vulnerability
    
The program takes on a breadth-first approach to generate an attack graph, beginning with the vulnerabilities associated with the entry hosts as input by the user.   

### Event Sequence Reconstruction
To chain up relevant events together, the program goes through the event logs (hosted within Splunk) in reverse chronological order from the notable event while doing a backwards depth-first traversal on the attack graph starting from where a notable event has occurred concurrently. At each node during the traversal, the event logs dictate the path the algorithm takes:
* Traverse from a State node to a preceding Vulnerability node if an exploitation event for that vulnerability has occurred
* Traverse from a Vulnerability node to a preceding State node if the vulnerability event occurred when the attacker was initially at the preceding state node's host (by checking the source of the event), or if there is an event involving this State node (source) and the vulnerable node (destination)

An event sequence / attack path is complete when an event originating from an external IP address to an entry host has been identified. 

### Listing of Subsequent Attack Paths
The program generates all possible simple paths from the state note of the notable event to all crown jewels, as specified by the user. The hosts passed through, ports used, access levels gained and vulnerabilities exploited for each path are printed.

## Assumptions
* All vulnerabilities that can or will be exploited are known
* Log entries are tagged with a description of the event that occurred
* There is a one-to-one mapping of a CVE ID to an event description
* Firewalls cannot be compromised and their rules will always be followed
* At the point of the notable event, the attacker's access level is known
* An IP address belonging to a host in the network can be accurately resolved to its hostname
* The event set is finite and can be searched through in a feasible amount of time 

## Future Work 

#### Interfacing with Skybox Security (or other network assurance tools)
The current solution reads in CSV files containing information about connectivity between network hosts and vulnerability occurrences within the network. To make the solution more scalable, integration with the Skybox tool will be required. The Skybox tool will be able to automatically compute the reachability of hosts and returns the vulnerabilities associated with each node. 

#### Detection of vulnerability exploitation from events
Currently, the user provides a rigid one-to-one mapping of CVE to event description. However, realistically, the act of exploiting a vulnerability can manifest itself as several events and the event descriptions might not be so predictable. Improvements can be made to use regex expressions to better identify CVE exploitations from events.

#### A GUI that can display the attack paths on a network topology
A GUI can be implemented to improve readability of attack paths, especially on a scaled-up version of a network.

#### More discrete User Access Levels
None and Root are already unique. However, User is not always homogeneous. As there are different users, they would have specific access to different programs which blocks others. As such, we can define different Users in a Node as 1.x e.g. 1.1, 1.2, 1.3 (recall that the prefix of 1 is taken by our program to be the general form of User). Therefore, this will paint a more discrete attack path.

#### Prediction capabilities
Currently, to pre-emptively prevent the attacker from reaching the crown jewels, all possible paths leading to them are listed by the program. To aid the defender in planning a more focused course of action, the program can predict which paths are more likely to be taken by the attacker. This can be performed in many ways, such as:
* tagging events to a phase in the cyber kill chain
* analysis of the attacker's intention and capabilities
* analysis of the level of difficulty of taking each possible path

Machine learning can make use of attacks that have happened in the past to achieve the above methods.
