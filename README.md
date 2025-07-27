
# Incident Response Automation

An online tool designed to automate incident response by scanning and monitoring network log data to detect cyber-attacks, analyze threats, and isolate affected systems to prevent further spread.

## 🔍 Overview

This project uses **Wireshark's network attack detection API** to identify malicious activities in network logs. The application provides a structured process for incident response, aiming to minimize damage, contain the threat, and recover from incidents.

## ⚙️ Features

- **New User Sign-Up** – Register new users to access the platform.
- **User Login** – Secure authentication to access functionality.
- **Data Collection & Incident Detection** – Upload network logs and detect threats using scanning APIs.
- **Alert Analysis** – Visualize attacks by generating graphs with activity types, IPs, ports, and frequencies.

## 🧪 How It Works

1. Upload network log data.
2. The system scans for abnormal/malicious traffic.
3. Generates alerts and detailed reports.
4. Displays graphs categorizing attacks (e.g., DDOS, port scans).

## 🖼️ Screenshots

> See the `SCREENS.docx` file for a full walkthrough of UI screens and interactions.

## 🚀 Getting Started

### Prerequisites

- Python 3.7.2
- MySQL

### Installation Steps

1. Clone the repository.
2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Set up the database:
   - Install MySQL.
   - Open the MySQL console and run the SQL commands in `database.txt`.
4. Start the project:
   ```bash
   double-click run.bat
   ```
5. Open your browser and navigate to:
   ```
   http://127.0.0.1:8000/index.html
   ```

## 📈 Technologies Used

- Python
- Wireshark API
- MySQL
- HTML/CSS (for UI)

## 📊 Output

- Attack detection by IP and port
- Graphs showing attack types vs. frequency
- Differentiation of normal vs. malicious packets

## 📂 Dataset

> *(If applicable, include a public link to a sample dataset or log files used for testing)*

## 🛡️ Use Case

Ideal for organizations or researchers needing an automated method to test and visualize cybersecurity incidents using real network logs.
