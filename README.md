# CS5584 Class Project - Embedding Machine Learning Into Programmable Switches

Description for files and folders:
* datasets/ : dataset for training and testing decision tree and neural network, taken from this site (https://research.unsw.edu.au/projects/unsw-nb15-dataset)
* images/ : images generated for report
* models/ : model checkpoint while being trained
* 1sw_demo.py , p4_mininet.py , commands.txt : throughput testing utilities
* requirements.txt : requirement for training the model and running the throughput test
* script.ipynb : script for training decision tree and neural network, as well as producing figures for report (adapted from https://github.com/nec-research/n3ic-nsdi22/tree/master)
* *.p4 : P4 source code

## How to Train the Decision Tree and BNN
1. Make a new virtual environment
```
python3 -m venv .venv
source .venv/bin/activate
```
2. Install all requirements
```
pip install -r requirements.txt
```
3. Run all cell in script.ipynb

## How to Run Throughput Test
1. Start a Ubuntu 20.04 VM from this repository (https://github.com/p4lang/tutorials). This VM already includes all dependency to compile and running P4 program inside the switches
2. Choose one P4 program to be tested (basic.p4, dt.p4 or nn.p4) and compile it. It will create a json file that would be fed into the switches.
```
p4c --target bmv2 --arch v1model basic.p4
``` 
3. Run simple topology. It will open up a mininet CLI.
```
sudo python3 1sw_demo.py --behavioral-exe simple_switch --json basic.json --num-hosts 2
```
4. Run this inside the mininet CLI, keep note the PIDs for those two hosts
```
mininet> dump
mininet> <... pid=123>
mininet> <... pid=124>
```

5. Open two new terminals and run this to connect to the hosts
```
sudo mnexec -a PUT_PID_HERE bash
```

6. Insert routing table entries
```
simple_switch_CLI < commands.txt
```

7. Ensure all hosts are connected by running this inside mininet CLI
```
mininet> pingall
```

8. Inside host 2, run an iperf server
```
iperf -s
```

9. From host 1, run an iperf client, running test to 10.0.1.10 (host 2's IP address)
```
iperf -c 10.0.1.10
```
