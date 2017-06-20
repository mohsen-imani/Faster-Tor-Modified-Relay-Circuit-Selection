# Modified Relay Selection and Circuit Selection For Faster Tor
This repo contains the source code of our project on improving the Tor performance. The project has two parts: Modified Circuit Selection and Modified Relay Selection. We implemented our changes on Tor version 2.5.12. Our modified Tor source code is in directory mytors/all-in-one.
# Circuit Selection.
The client's traffic in Tor goes through a three-hop encrypted channel, called a circuit. When the user makes a request, such as for a webpage, Tor attaches the new stream (by opening a SOCKS connection) to a circuit. The Tor client builds circuits preemptively based on the client's use or immediately if there is no current circuit to handle the stream. Tor currently does not use any performance criteria in selecting a circuit. In this project, we evaluate using the length of the circuits, their congestion, the Round Trip Time (RTT), or a combination of them in choosing a fast circuit. We also find that the number of available circuits in Tor is often small, between one and three circuits, such that picking the best circuit for performance does not have much effect in practice. As the number of available circuits increases, the chance of finding a fast and high performance circuit should increase. 
For more information, check out our paper: 

# Relay Selection.
For circuit selection to be effective, some of the available circuits must be reasonably high performing. To improve the chances of this, we modify the relay selection mechanism to build short and high-bandwidth circuits. Tor clients select paths in a way that balances traffic load among the relays according to their advertised bandwidths, but they do not make any consideration for the locations of relays relative to the clients, their destinations, or the other relays in the path. Paths can jump around the globe, which is  intuitively good for anonymity but measurably bad for performance. Prior work has examined improving path selection in Tor for better performance, considering factors such as bandwidth, congestion, latency, and location.
Wacek et al [2]. performed a comprehensive study of path selection, and they found that congestion-aware routing [1] offers the best combination of performance and anonymity among the tested approaches. They also found that approaches that emphasized latency but failed to consider bandwidth had poor performance, and they suggested that an approach that optimized both latency and bandwidth could do better than any of their tested approaches. In this project, we take on this suggestion and explore designs that address both criteria.
For more information, check out our paper: 



# Setting
In our modified Tor source code we have some parameters that should be set in order to activate different functionalities of our code. These parameters should be added to torrc files, otherwise the code will consider the default values. Check file mytors/all-in-one-2.5.12/src/or/config.c to see the default values.
GeoPath: should point to GeoLiteCity.dat file. In this repo it is in requirements/GeoIP-datasets.
MYIP: the client's IP address.
MYLAT: the client's latitude.
MYLON: the client's longitude.
ClientOnly: this parameter should be always 1 because our modifications are only on the client side.

VANILLA: 
- 1: runs the code as the vanilla Tor, all our methods will be deactivated
- 2: activates our circuit selection mechanisms.
- 3: activates the Congestion-Aware routing [1].
- 4: activates our modifications for evaluating the number of available circuits.
- 0: activates our relay selection modifications.

# Case 1: Circuit Selection.
In this case, whenever we want to pick a circuit for a stream, we first pick CIRC_NEEDED circuits based on the first criterion and then we choose the best one based on the second criterion. The circuit selection method is chosen by parameter  CIRC_SELECT.
- VANILLA is 2.
- CIRC_SELECT = 1: Length then congestion, Select the CIRC_NEEDED lowest RTTs and pick the shorter one.
- CIRC_SELECT = 2: Congestion then length, Select the CIRC_NEEDED lowest congestion times and pick the shorter circuit.
- CIRC_SELECT = 3: RTT Only, Pick the circuit with the lowest RTT.
- CIRC_SELECT = 4: Congestion Only, Pick the circuit with the lowest congestion time.
- CIRC_SELECT = 5: RTT then length, Select the CIRC_NEEDED lowest RTTs and pick the shorter one.
- CIRC_SELECT = 6: Length then RTT, Select the CIRC_NEEDED shortest circuits and pick the lower RTT. 
- CIRC_SELECT = 7: Length Only, Pick the shortest circuit.
- CIRC_SELECT = 8: RTT then Congestion, Select the CIRC_NEEDED circuits with the lowest RTTs and pick the lower congestion time. 
- CIRC_SELECT = 9:Congestion then RTT, Select the CIRC_NEEDED circuits with lowest congestion times and pick the lower RTT. 
In our default setting, CIRC_NEEDED = 2.

# Case 2: Congestion-Aware Routing.
This case runs the Congestion-Aware routing. The only parameter that you may need to change is  CUTTOFF.
- VANILLA is 3.
- CUTOFF: this option controls the threshold for pruning the circuits. The default value is 600 mseconds which means circuits their median congestion time is greater than 600 mseconds will be used. 

# Case 3: Open Circuits.
In this case, we activate our modification to increase the number of pre-built circuits, or available circuits. The code checks the number of pre-built circuits every second and if they are less than OPEN_CIRCUITS_ISEC, it will open new circuits to have the desired number of circuits.
 - VANILLA is 4.
- OPEN_CIRCUITS_ISEC: is the number of circuits that they should be open in any given time.
- You can change the CIRC_SELECT to change the circuit selection mechanism as well.
- CIRC_LIFE_TIME_ISEC: It kills the unused circuits after CIRC_LIFE_TIME_ISEC minutes. The default is 5 minutes.
# Case 3: Relay Selection.
This setting activates our relay selection mechanism. Parameters that should be set here are:
- VANILLA is 0.
- ALPHA_ISEC: it should be set to a value between 0 and 100. It controls the share between bandwidth and distance in the relays' weight. It is the alpha in our design. Please check out our paper for the role of this parameter.
- LAMBDA: it should be set to a value between 0 and 100. It is the lambda in our design. Please check out our paper for the role of this parameter.
- CIRC_LIFE_TIME_ISEC: It kills the unused circuits after CIRC_LIFE_TIME_ISEC minutes. The default is 5 minutes.
- MIN_NUMBER_OF_CIRC_FOR_EACH_DEST: It checks to have MIN_NUMBER_OF_CIRC_FOR_EACH_DEST circuits to each popular destination.
- For choosing   CIRC_SELECT, please check function circuit_get_best_all_in_one in mytors/all-in-one-2.5.12/src/or/circuituse.c to find different circuit selection mechanism in this case. We have defined so many circuit selection mechanisms  for this case.





# References
[1]. Wang, T., Bauer, K., Forero, C., and Goldberg, I. Congestion-aware path selection for Tor. In FC (February 2012).

[2]. Wacek, C., Tan, H., Bauer, K., and Sherr, M. An empirical evaluation of relay selection in Tor. In NDSS (February 2013).


