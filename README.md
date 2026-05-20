# Network Monitoring and Defense System

## Project Purpose
The purpose of this project is to develop a real-time Network Monitoring and Defense System capable of detecting suspicious network activities such as:

- DDoS Attacks
- Port Scanning
- ARP Spoofing

The system provides a web-based dashboard for monitoring alerts, viewing audit logs, and managing detection settings to improve network security awareness and incident response.

---

## Features
- Real-time Packet Monitoring
- DDoS Detection
- Port Scan Detection
- ARP Spoofing Detection
- Alert Management System
- Audit Logging
- Login Authentication
- Adjustable Detection Thresholds
- Dashboard Monitoring Interface

---

## Technologies Used
- Python
- Flask
- MySQL
- HTML
- CSS
- JavaScript
- Scapy

---

## Project Structure

```bash
network-monitoring-system/
│
├── static/
│   ├── alerts.css
│   ├── dashboard.css
│   ├── logs.css
│   ├── settings.css
│   └── style.css
│
├── templates/
│   ├── alerts.html
│   ├── dashboard.html
│   ├── login.html
│   ├── logs.html
│   └── settings.html
│
├── app.py
├── network_monitor.sql
└── README.md
```

---

## Database Setup

1. Open phpMyAdmin
2. Create a database named:

```bash
network_monitor
```

3. Import the SQL file:

```bash
network_monitor.sql
```

---

## Installation

Install required libraries:

```bash
pip install flask mysql-connector-python scapy
```

---

## How to Run the Project

Run the Flask application:

```bash
python app.py
```

Open browser:

```bash
http://127.0.0.1:5000
```

---

## Default Login
Use the admin credentials stored in the database.

---

## System Modules
- Dashboard Module
- Alerts Module
- Logs Module
- Settings Module
- Authentication Module
- Packet Capture Module
## Researchers / Developers
- Macapayag, Ryan
