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
Our implementation:

#IDPS

import pandas as pd
import pyshark
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import pickle
import numpy as np

# Step 1: Capture Network Traffic using PyShark
def capture_packets(interface='wlan0', timeout=10):
    # List to store packet information
    data = []
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=timeout)

    # Extract relevant features from each packet
    for packet in capture:
        try:
            print(f"Processing packet: {packet}")
            protocol = packet.transport_layer
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet[protocol].srcport if hasattr(packet[protocol], 'srcport') else 'N/A'
            dst_port = packet[protocol].dstport if hasattr(packet[protocol], 'dstport') else 'N/A'
            length = int(packet.length)
            timestamp = float(packet.sniff_time.timestamp())
            
            data.append([protocol, src_ip, dst_ip, src_port, dst_port, length, timestamp])
        except AttributeError as e:
            print(f"Error processing packet: {e}")
            continue  # Skip packets that don't have the required fields

    # Convert data to DataFrame
    df = pd.DataFrame(data, columns=['Protocol', 'Src_IP', 'Dst_IP', 'Src_Port', 'Dst_Port', 'Length', 'Timestamp'])
    
    if df.empty:
        print("No packets captured within the specified timeout.")
        exit()

    print(f'Captured data:\n{df.head()}')
    return df

# Step 2: Aggregate Traffic Data
def aggregate_data(df):
    # Convert timestamp to datetime and set as index for resampling
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], unit='s')
    df.set_index('Timestamp', inplace=True)

    # Resample data every 1 second and calculate statistics
    aggregated_df = df.resample('1S').agg({
        'Length': 'sum',                # Total bytes sent
        'Src_IP': 'nunique',             # Unique source IPs
        'Dst_IP': 'nunique',             # Unique destination IPs
    }).fillna(0)  # Fill missing values with 0 to handle empty periods

    # Rename columns for clarity
    aggregated_df.rename(columns={'Length': 'Total_Bytes', 'Src_IP': 'Unique_Src_IPs', 'Dst_IP': 'Unique_Dst_IPs'}, inplace=True)
    
    print(f"Aggregated data:\n{aggregated_df.head()}")
    return aggregated_df

# Step 3: Train Anomaly Detection Model (Isolation Forest)
def train_anomaly_detection_model(data):
    # Select only numerical columns for model training
    data_for_training = data[['Total_Bytes', 'Unique_Src_IPs', 'Unique_Dst_IPs']]
    
    # Initialize the scaler and isolation forest model
    scaler = StandardScaler()
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)

    # Scale data
    X_scaled = scaler.fit_transform(data_for_training)

    # Fit the model
    model.fit(X_scaled)

    # Save the model and scaler
    with open('anomaly_detection_model.pkl', 'wb') as file:
        pickle.dump((model, scaler), file)
    print("Model and scaler saved as 'anomaly_detection_model.pkl'")

# Step 4: Detect Anomalies
def detect_anomalies(new_data):
    # Select only numerical columns for anomaly detection
    new_data_for_detection = new_data[['Total_Bytes', 'Unique_Src_IPs', 'Unique_Dst_IPs']]
    
    # Load the model and scaler
    with open('anomaly_detection_model.pkl', 'rb') as file:
        model, scaler = pickle.load(file)

    # Scale new data
    new_data_scaled = scaler.transform(new_data_for_detection)

    # Predict anomalies
    predictions = model.predict(new_data_scaled)
    anomalies = [1 if p == -1 else 0 for p in predictions]  # 1 indicates anomaly, 0 indicates normal

    # Add prediction results to the DataFrame
    new_data['Anomaly'] = anomalies
    return new_data

# Main Execution
if _name_ == "_main_":
    try:
        # Step 1: Capture network packets
        raw_data = capture_packets(interface='wlan0', timeout=10)
        
        # Step 2: Aggregate captured data
        aggregated_data = aggregate_data(raw_data)

        # Step 3: Train anomaly detection model on aggregated data
        train_anomaly_detection_model(aggregated_data)

        # Step 4: Detect anomalies in new data (re-run packet capture for testing)
        new_data = aggregate_data(capture_packets(interface='wlan0', timeout=5))  # Capture new data for testing
        anomalies = detect_anomalies(new_data)
        
        # Print detected anomalies
        print("Detected anomalies:")
        print(anomalies[anomalies['Anomaly'] == 1])

    except Exception as e:
        print(f"An error occurred: {e}")


# Detection of anomalies

import pandas as pd
import pyshark
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import pickle
import numpy as np

# Step 1: Capture Network Traffic using PyShark
def capture_packets(interface='wlan0', timeout=10):
    # List to store packet information
    data = []
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=timeout)

    # Extract relevant features from each packet
    for packet in capture:
        try:
            print(f"Processing packet: {packet}")
            protocol = packet.transport_layer
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet[protocol].srcport if hasattr(packet[protocol], 'srcport') else 'N/A'
            dst_port = packet[protocol].dstport if hasattr(packet[protocol], 'dstport') else 'N/A'
            length = int(packet.length)
            timestamp = float(packet.sniff_time.timestamp())
            
            data.append([protocol, src_ip, dst_ip, src_port, dst_port, length, timestamp])
        except AttributeError as e:
            print(f"Error processing packet: {e}")
            continue  # Skip packets that don't have the required fields

    # Convert data to DataFrame
    df = pd.DataFrame(data, columns=['Protocol', 'Src_IP', 'Dst_IP', 'Src_Port', 'Dst_Port', 'Length', 'Timestamp'])
    
    if df.empty:
        print("No packets captured within the specified timeout.")
        exit()

    print(f'Captured data:\n{df.head()}')
    return df

# Step 2: Aggregate Traffic Data
def aggregate_data(df):
    # Convert timestamp to datetime and set as index for resampling
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], unit='s')
    df.set_index('Timestamp', inplace=True)

    # Resample data every 1 second and calculate statistics
    aggregated_df = df.resample('1S').agg({
        'Length': 'sum',                # Total bytes sent
        'Src_IP': 'nunique',             # Unique source IPs
        'Dst_IP': 'nunique',             # Unique destination IPs
    }).fillna(0)  # Fill missing values with 0 to handle empty periods

    # Rename columns for clarity
    aggregated_df.rename(columns={'Length': 'Total_Bytes', 'Src_IP': 'Unique_Src_IPs', 'Dst_IP': 'Unique_Dst_IPs'}, inplace=True)
    
    print(f"Aggregated data:\n{aggregated_df.head()}")
    return aggregated_df

# Step 3: Train Anomaly Detection Model (Isolation Forest)
def train_anomaly_detection_model(data):
    # Select only numerical columns for model training
    data_for_training = data[['Total_Bytes', 'Unique_Src_IPs', 'Unique_Dst_IPs']]
    
    # Initialize the scaler and isolation forest model
    scaler = StandardScaler()
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)

    # Scale data
    X_scaled = scaler.fit_transform(data_for_training)

    # Fit the model
    model.fit(X_scaled)

    # Save the model and scaler
    with open('anomaly_detection_model.pkl', 'wb') as file:
        pickle.dump((model, scaler), file)
    print("Model and scaler saved as 'anomaly_detection_model.pkl'")

# Step 4: Detect Anomalies
def detect_anomalies(new_data):
    # Select only numerical columns for anomaly detection
    new_data_for_detection = new_data[['Total_Bytes', 'Unique_Src_IPs', 'Unique_Dst_IPs']]
    
    # Load the model and scaler
    with open('anomaly_detection_model.pkl', 'rb') as file:
        model, scaler = pickle.load(file)

    # Scale new data
    new_data_scaled = scaler.transform(new_data_for_detection)

    # Predict anomalies
    predictions = model.predict(new_data_scaled)
    anomalies = [1 if p == -1 else 0 for p in predictions]  # 1 indicates anomaly, 0 indicates normal

    # Add prediction results to the DataFrame
    new_data['Anomaly'] = anomalies
    return new_data

# Main Execution
if _name_ == "_main_":
    try:
        # Step 1: Capture network packets
        raw_data = capture_packets(interface='wlan0', timeout=10)
        
        # Step 2: Aggregate captured data
        aggregated_data = aggregate_data(raw_data)

        # Step 3: Train anomaly detection model on aggregated data
        train_anomaly_detection_model(aggregated_data)

        # Step 4: Detect anomalies in new data (re-run packet capture for testing)
        new_data = aggregate_data(capture_packets(interface='wlan0', timeout=5))  # Capture new data for testing
        anomalies = detect_anomalies(new_data)
        
        # Print detected anomalies
        print("Detected anomalies:")
        print(anomalies[anomalies['Anomaly'] == 1])

    except Exception as e:
        print(f"An error occurred: {e}")

