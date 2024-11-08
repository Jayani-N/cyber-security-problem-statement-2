# Problem Statement: Rogue Wi-Fi Access Point Detection and Network Packet Analyzer for Intrusion Detection

## Objective
In the age of wireless connectivity, the threat landscape has expanded significantly, with rogue Wi-Fi access points becoming a common tool for attackers to intercept, manipulate, or steal sensitive data from unsuspecting users. Simultaneously, network security is constantly under threat from malicious actors who deploy malware, initiate unauthorized data transfers, or exploit vulnerabilities to gain unauthorized access. The objective of this challenge is to build a dual-purpose system that can (1) detect rogue Wi-Fi access points in the network and (2) analyze network traffic to identify potential security threats, enhancing the overall security posture of a given environment.

---

## Part 1: Rogue Wi-Fi Access Point Detection
1. **Rogue Access Point Scanning**  
   The system should regularly scan the surrounding environment for Wi-Fi access points and identify unauthorized or untrusted access points that pose security risks. This includes detecting access points masquerading as legitimate networks, commonly known as “evil twins,” which are frequently used in man-in-the-middle (MitM) attacks.

2. **Access Point Validation**  
   Identify access points based on a predefined list of trusted networks, checking for anomalies such as duplicated network names (SSIDs), suspicious MAC addresses, or other irregularities that could indicate a rogue access point. Flag any access points that do not match trusted profiles.

3. **Alert System**  
   Upon identifying a rogue access point, the system should immediately notify users or administrators with relevant information, such as the SSID, MAC address, and signal strength of the rogue AP. The alerts should be configurable and sent via email, SMS, or dashboard notifications, enabling quick response to potential security breaches.

---

## Part 2: Network Packet Analyzer Tool
1. **Real-Time Packet Capture**  
   Develop a tool that captures network traffic in real time, analyzing packets traversing the network. This tool should support major network protocols such as TCP, UDP, and HTTP and allow filtering based on protocol types, packet sources, destinations, and data content.

2. **Packet Filtering and Analysis**  
   Implement features to filter and inspect packets based on specific criteria, focusing on detecting unusual patterns such as repeated access attempts, unexpected protocol behavior, and irregular packet sizes. The system should analyze and flag malicious packets, unauthorized data transfers, or other suspicious activities.

3. **Anomaly Detection**  
   Integrate anomaly detection algorithms that use statistical, heuristic, or machine learning methods to identify deviations from typical network behavior. The system should detect signs of potential intrusions, including port scans, DDoS patterns, and command-and-control traffic.

4. **Detailed Reporting and Visualization**  
   Create a reporting system that generates summaries and detailed reports of captured traffic and flagged anomalies. This should include traffic data visualizations, highlighting key metrics such as protocol distribution, top source and destination addresses, packet frequency over time, and identified threats.

5. **User-Friendly Dashboard**  
   Design an intuitive, accessible dashboard that displays real-time network status, rogue access point detections, and packet analysis results. The dashboard should allow administrators to monitor network health, review alerts, and gain insights into traffic patterns, enabling proactive responses to emerging threats.

---

## Deliverables
1. **Wi-Fi Access Point Scanner Module**  
   A standalone or integrated tool capable of detecting and alerting on rogue access points, offering details on suspected rogue devices.

2. **Network Packet Analyzer Module**  
   A tool for real-time packet capture, analysis, anomaly detection, and report generation. Should include visualizations that make network data easily interpretable.

3. **Unified Dashboard Interface**  
   A user interface that integrates both modules, allowing seamless monitoring and alert management for administrators.

---

### Note: This serves only as a reference example. Innovative ideas and unique implementation techniques are highly encouraged and warmly welcomed!
