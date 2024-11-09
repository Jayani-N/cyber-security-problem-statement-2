# Problem Statement: Rogue Wi-Fi Access Point Detection and Network Packet Analyzer for Intrusion Detection

Prerequisites:
# Install the dependencies

      python3
   
      subprocess
   
      re
   
      time
   
      datetime
   
      defaultdict
   
      logging
   
      IsolationForest
   
      numpy
   
      argparse

# Step-by-Step Implementation of the code:

Step 1: Detecting rouge ap's using mac tethering,radio frequencies and signals

Step 2: Anamoly detection implementation with ML to identify unusual traffic patterns

Step 3: Detecting credential harvesting attacks, MITM, Ransomware, DOS & DDOS

Step 4: Dynamically adjusting the traffic threshold based on average traffic in previous intervals

Step 5: Alerting users using push notifications when detecting an unauthorized access

# Output Screenshots


![img1](https://github.com/user-attachments/assets/b78cca5f-88df-44e2-873f-f8422b6c1345)

![img2](https://github.com/user-attachments/assets/5bca5795-5ed8-4016-9f3a-7ce69d9ea60a)

![img3](https://github.com/user-attachments/assets/222c427f-208e-40f1-bb22-21784038c211)


## To run this CLI tool, run the following command on the Linux (Debian) distributions terminal:


```sh
python network_monitor.py --authorized-macs "your_device_mac" --authorized-aps "access_point_mac" --traffic-threshold 100 --dos-threshold 500 --monitor-interval 10 --interface {{your_interface_name}}










