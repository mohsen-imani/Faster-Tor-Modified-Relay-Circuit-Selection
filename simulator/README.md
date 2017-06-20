# Relay Selection Simulator.

This code simulates our relay selection mechanism. It considers an adversary with a certain amount of bandwidth and a certain number of clients.
The simulator can be run in a way that it only generates paths without adding the adversarial relays to the network to be able to measure the entropy
or it can add the adversarial relays to compute the compromised rate. The adversary's relays are added based on the defined attack scenarios.

attack == "CLIENT", the attacker targets the client, puts all of his relays in the client's location.

attack == 'DEST' the attacker targets the destination, puts all of his relays in the destination's location.

attack == 'BOTH' the attacker targets both the client and the destination, puts all of his relays in their location.

attack == 'NON-TARGETED', the attacker adds his relays in the random locations in the network.

The simulator first considers a scaled-down Tor network, 30% of Tor network in 2015-10-31-23-00-00-consensus.
It also considers 200 clients that are located in the top countries which using Tor, and in each country the locations are picked based on the population of the cities.

# Usage:
python simulator.py [-h] [-f FRACTION] [-g GUARD] [-a ATTACK] [-e ENTROPY]
                    [-l LAM] [-p ALPHA] [-w PROCESS] [-c CIRCUITS]
