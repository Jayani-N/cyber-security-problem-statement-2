

# Our implementation:

# IDPS (Intrusion Detection & Prevention System)


      import subprocess
      
      import re
      
      import time
      
      from datetime import datetime
      
      from collections import defaultdict
      
      import logging

      # Log file for network activity
      LOG_FILE = "network_activity.log"

      # Regular expressions to extract MAC addresses, IP addresses, and frames
      mac_regex = re.compile(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}")
      ip_regex = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
      deauth_regex = re.compile(r"Deauthentication frame")
      ssid_regex = re.compile(r"SSID: ([^\s]+)")  # Assuming SSID is included in packet info

      # Dictionary to keep track of traffic counts per IP and per MAC for DoS detection
      traffic_monitor = defaultdict(int)
      dos_monitor = defaultdict(int)  # Monitor traffic from MAC addresses to detect DoS
      interval_traffic_data = []  # List to store traffic for dynamic threshold calculation

      # Setup logging
      logging.basicConfig(
          level=logging.INFO,
          format='%(asctime)s - %(levelname)s - %(message)s',
          handlers=[
              logging.FileHandler(LOG_FILE),
              logging.StreamHandler()
          ]
      )

      def get_user_input():
          """Get configuration values from the user."""
          print("Configure Network Monitoring Script")

    # Authorized MAC Addresses
    authorized_macs = set(input("Enter authorized MAC addresses (comma-separated): ").split(","))
    authorized_macs = {mac.strip() for mac in authorized_macs}

    # Authorized AP MAC Addresses
    authorized_aps = set(input("Enter authorized AP MAC addresses (comma-separated): ").split(","))
    authorized_aps = {ap.strip() for ap in authorized_aps}

    # Traffic threshold
    try:
        traffic_threshold = int(input("Enter traffic threshold (packets per IP per interval): "))
    except ValueError:
        traffic_threshold = 100  # Default value

    # DoS threshold
    try:
        dos_threshold = int(input("Enter DoS threshold (packets per MAC): "))
    except ValueError:
        dos_threshold = 500  # Default value

    # Monitor interval
    try:
        monitor_interval = int(input("Enter monitoring interval in seconds: "))
    except ValueError:
        monitor_interval = 10  # Default value

    # Network interface
    interface = input("Enter network interface to monitor (e.g., wlan0): ").strip()

    return authorized_macs, authorized_aps, traffic_threshold, dos_threshold, monitor_interval, interface

      def log_activity(message, level=logging.INFO):
          """Log activity with a timestamp to a log file and print to console."""
          logging.log(level, message)

      def send_popup_notification(title, message):
          """Send a system pop-up notification."""
          try:
              subprocess.run(["notify-send", title, message], check=True)
              log_activity(f"Popup notification sent: {title} - {message}", level=logging.INFO)
          except subprocess.CalledProcessError as e:
              log_activity(f"Failed to send pop-up notification: {e}", level=logging.ERROR)

      def analyze_traffic(ip_src, traffic_threshold):
          """Check if traffic from an IP source exceeds threshold within interval."""
          traffic_monitor[ip_src] += 1
          if traffic_monitor[ip_src] > traffic_threshold:
              message = f"Unusual traffic detected from IP: {ip_src}"
              log_activity(message, level=logging.WARNING)
              send_popup_notification("Unusual Traffic Detected", message)

      def monitor_dos(mac_src, dos_threshold):
          """Check if traffic from a MAC address exceeds DoS threshold."""
          dos_monitor[mac_src] += 1
          if dos_monitor[mac_src] > dos_threshold:
              message = f"Potential DoS attack detected from MAC: {mac_src}"
              log_activity(message, level=logging.ERROR)
              send_popup_notification("Potential DoS Attack Detected", message)
              try:
                  subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac_src, "-j", "DROP"], check=True)
                  log_activity(f"Blocked DoS source MAC address: {mac_src}", level=logging.INFO)
              except subprocess.CalledProcessError as e:
                  log_activity(f"Failed to block MAC {mac_src}: {e}", level=logging.ERROR)

      def detect_rogue_aps(line, authorized_aps):
          """Detect rogue APs based on unrecognized AP MAC addresses and SSIDs."""
          ap_match = mac_regex.search(line)
          ssid_match = ssid_regex.search(line)
          if ap_match:
              ap_mac = ap_match.group()
              if ap_mac not in authorized_aps:
                  message = f"Rogue AP detected with MAC: {ap_mac}"
                  log_activity(message, level=logging.WARNING)
                  send_popup_notification("Rogue AP Detected", message)

    if ssid_match:
        ssid = ssid_match.group(1)
        message = f"Rogue SSID detected: {ssid}"
        log_activity(message, level=logging.WARNING)
        send_popup_notification("Rogue SSID Detected", message)

      def detect_deauth_attack(line):
          """Detect Deauthentication (Deauth) frames."""
          if deauth_regex.search(line):
              message = "Deauthentication attack detected"
              log_activity(message, level=logging.ERROR)
              send_popup_notification("Deauthentication Attack Detected", message)

      def adjust_traffic_threshold(interval_traffic_data):
          """Dynamically adjust the traffic threshold based on average traffic in previous intervals."""
          if interval_traffic_data:
              avg_traffic = sum(interval_traffic_data) / len(interval_traffic_data)
              new_threshold = int(avg_traffic * 1.5)  # Increase threshold by 50% of average traffic
              log_activity(f"Adjusted traffic threshold to: {new_threshold}", level=logging.INFO)
              return new_threshold
          return TRAFFIC_THRESHOLD

      def monitor_network(interface, authorized_macs, authorized_aps, traffic_threshold, dos_threshold, monitor_interval):
          print("Starting network monitoring...")
          start_time = time.time()

    try:
        while True:
            # Capture packets with tcpdump
            result = subprocess.run(
                ["sudo", "tcpdump", "-i", interface, "-nn", "-c", "10", "not", "ether", "src", "ff:ff:ff:ff:ff:ff"], 
                capture_output=True, 
                text=True
            )
            if result.returncode != 0:
                log_activity("Error running tcpdump", level=logging.ERROR)
                continue

            lines = result.stdout.splitlines()
            
            for line in lines:
                log_activity(f"Processing line: {line}", level=logging.DEBUG)
                
                # Extract MAC address and IP address
                mac_match = mac_regex.search(line)
                ip_match = ip_regex.search(line)
                
                if mac_match:
                    mac_address = mac_match.group()
                    if mac_address not in authorized_macs:
                        message = f"Unauthorized MAC address detected: {mac_address}"
                        log_activity(message, level=logging.WARNING)
                        send_popup_notification("Unauthorized MAC Detected", message)
                        try:
                            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-m", "mac", "--mac-source", mac_address, "-j", "DROP"], check=True)
                            log_activity(f"Blocked unauthorized MAC address: {mac_address}", level=logging.INFO)
                        except subprocess.CalledProcessError as e:
                            log_activity(f"Failed to block unauthorized MAC {mac_address}: {e}", level=logging.ERROR)
                        continue
                
                # Detect rogue APs and Deauth attacks
                detect_rogue_aps(line, authorized_aps)
                detect_deauth_attack(line)
                
                if ip_match:
                    ip_src = ip_match.group()
                    analyze_traffic(ip_src, traffic_threshold)
                
                # Monitor for DoS attacks based on MAC address
                if mac_match:
                    mac_src = mac_match.group()
                    monitor_dos(mac_src, dos_threshold)

            # Store traffic count for dynamic threshold adjustment
            interval_traffic_data.append(sum(traffic_monitor.values()))

            # Adjust traffic threshold based on the traffic pattern
            traffic_threshold = adjust_traffic_threshold(interval_traffic_data)
            
            # Check if the monitoring interval has elapsed
            if time.time() - start_time >= monitor_interval:
                # Reset traffic counts for the next interval
                traffic_monitor.clear()
                dos_monitor.clear()
                interval_traffic_data.clear()
                start_time = time.time()

            time.sleep(1)

    except KeyboardInterrupt:
        print("Network monitoring stopped.")

      if _name_ == "_main_":
    # Get user input for configuration values
         authorized_macs, authorized_aps, traffic_threshold, dos_threshold, monitor_interval, interface = get_user_input()

    # Start network monitoring with user-configured settings
         monitor_network(interface, authorized_macs, authorized_aps, traffic_threshold, dos_threshold, monitor_interval)


# Detection of anomalies (Using ML Model)

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

