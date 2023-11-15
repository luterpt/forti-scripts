#!/usr/bin/env python3

import requests
from getpass import getpass
import urllib3
from datetime import datetime
import time
import csv
import subprocess

# This script is designed to authenticate against an API to obtain a session token.
# It then monitors memory usage and CPU usage, providing real-time updates.
# If memory usage exceeds a specified threshold, it triggers a notification and executes a PowerShell command.

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALERT_THRESHOLD = 23  # Memory usage threshold for alerting (%)

def authenticate(hostname, username, password):
    login_url = f'https://{hostname}/logincheck'
    session = requests.session()

    # Send a POST request to the login endpoint with the provided credentials
    login_payload = {'username': username, 'secretkey': password}
    response = session.post(login_url, data=login_payload, verify=False)  # Note: Use verify=False for self-signed SSL certificates

    # Check if login was successful
    if response.ok:
        print("Authentication successful!")
        return session
    else:
        print("Authentication failed. Please check your credentials.")
        return None

def convert_timestamp(timestamp):
    # Convert Unix timestamp to human-readable format
    return datetime.utcfromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')

def get_resource_usage(session, hostname):
    api_url = f'https://{hostname}/api/v2/monitor/system/resource/usage?scope=global'

    # Send a GET request to the API endpoint using the established session
    response = session.get(api_url, verify=False)  # Note: Use verify=False for self-signed SSL certificates

    # Check if the API request was successful
    if response.ok:
        return response.json()
    else:
        print("Failed to retrieve resource usage. Please check your session.")
        return None
# We Will use a NTFY alert system , Change the endpoint first
def send_alert_and_execute_command(mem_value, timestamp):
    alert_url = 'https://ntfy.sh/-Change-This-Endpoint'
    alert_body = f"Memory Usage Exceeded: {mem_value}% at {timestamp}"

    # Send a POST request with the alert body
    response = requests.post(alert_url, data=alert_body)

    # Check if the alert was successfully sent
    if response.ok:
        print("Alert sent successfully!")

        # Execute the command when the threshold is exceeded
        if mem_value > ALERT_THRESHOLD:
            execute_command()

    else:
        print("Failed to send alert.")
        #below is the command to launch the powershell script - you my have to specify the full path
def execute_command():
    command = r'powershell ipconfig'
    
    try:
        subprocess.Popen(command, shell=True)
        print("Command initiated successfully!")
    except Exception as e:
        print(f"Error initiating command: {e}")

def log_to_csv(cpu_values, mem_values):
    with open('resource_usage_log.csv', mode='a', newline='') as csvfile:
        fieldnames = ['Timestamp', 'CPU Usage (%)', 'Memory Usage (%)']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if csvfile.tell() == 0:  # Check if the file is empty
            writer.writeheader()

        latest_cpu_timestamp, latest_cpu_value = cpu_values[-1]
        latest_mem_timestamp, latest_mem_value = mem_values[-1]

        writer.writerow({
            'Timestamp': convert_timestamp(latest_cpu_timestamp),
            'CPU Usage (%)': latest_cpu_value,
            'Memory Usage (%)': latest_mem_value
        })

def print_resource_usage(resource_data):
    if resource_data:
        print("\nCPU Usage:")
        cpu_values = resource_data["results"]["cpu"][0]["historical"]["1-min"]["values"]
        latest_cpu_timestamp, latest_cpu_value = cpu_values[-1]
        print(f"Timestamp: {convert_timestamp(latest_cpu_timestamp)}, Value: {latest_cpu_value}%")

        print("\nMemory Usage:")
        mem_values = resource_data["results"]["mem"][0]["historical"]["1-min"]["values"]
        latest_mem_timestamp, latest_mem_value = mem_values[-1]
        print(f"Timestamp: {convert_timestamp(latest_mem_timestamp)}, Value: {latest_mem_value}%")

        # Log to CSV
        log_to_csv(cpu_values, mem_values)

        # Check if memory usage exceeds the threshold
        if latest_mem_value > ALERT_THRESHOLD:
            send_alert_and_execute_command(latest_mem_value, convert_timestamp(latest_mem_timestamp))
            print(f"Memory threshold Exceeded !! Logging Alert and Pulling the Trigger !!...")

    else:
        print("No resource data to display.")

if __name__ == "__main__":
    # Get user input for target hostname, username, and password
    target_hostname = input("Enter the target hostname: ")
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")

    # Authenticate and get a session
    session = authenticate(target_hostname, username, password)

    if session:
        try:
            while True:
                # Get resource usage data using the established session
                resource_usage_data = get_resource_usage(session, target_hostname)

                # Print human-readable resource usage data and send alert if needed
                print_resource_usage(resource_usage_data)

                # Sleep for a specified interval before polling again
                time.sleep(10)  # 10 seconds, adjust as needed
        except KeyboardInterrupt:
            print("\nExiting the Session. See Ya!")
