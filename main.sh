#!/bin/bash

# Install necessary tools
install_tools() {
  sudo apt update
  sudo apt install -y tshark wget curl zeek python3 jq gnome-terminal git
  git clone https://github.com/1aN0rmus/TekDefense-Automater.git /opt/automater
}

# Download the IOC file
download_ioc_file() {
  wget -O /tmp/iocs.txt $IOC_URL
}

# Live capture and processing of network traffic
capture_traffic_live() {
  tshark -i $INTERFACE -b filesize:$CAPTURE_LIMIT -T fields -e http.host -e dns.qry.name -e ip.dst | while read LOGLINE
  do
    echo $LOGLINE | tr ' ' '\n' | while read HOST; do
      if grep -q $HOST /tmp/iocs.txt; then
        generate_alert "Traffic detected to/from IOC: $HOST" "$LOGLINE"
      fi
    done
  done
}

# Check file hash against VirusTotal using Automater
check_files() {
  for FILE in ./extracted_files/*; do
    if [ -d $FILE ]; then
      continue
    fi
    FILE_HASH=$(sha256sum $FILE | cut -d' ' -f1)
    AUTOMATER_OUTPUT=$(python /opt/automater/Automater.py -d 2 $FILE_HASH)
    if echo $AUTOMATER_OUTPUT | grep -q 'malicious'; then
      generate_alert "Malicious file detected: $FILE" "$FILE_HASH" "$AUTOMATER_OUTPUT"
    fi
  done
}

#This function was created using chatgpt:
# Generate an alert
generate_alert() {
  ALERT_MESSAGE="$(date) ALERT: $1\nHash: $2\nVirusTotal report: $3"
  echo -e $ALERT_MESSAGE >> alerts.log
  
  # check if the terminal pid exists and is running
  if [ -n "$LIVE_TERMINAL_PID" ] && kill -0 $LIVE_TERMINAL_PID 2> /dev/null; then
    echo -e $ALERT_MESSAGE > /proc/$LIVE_TERMINAL_PID/fd/1
  fi
}

# Main function
main() {
  # Set parameters
  INTERFACE="eth0"
  CAPTURE_LIMIT="1000"
  IOC_URL="https://example.com/iocs.txt"

  # Check if parameters have been set by the user
  if [[ $IOC_URL == "https://example.com/iocs.txt" ]]; then
    echo "ERROR: Please set the script parameters before running."
    exit 1
  fi

  # User prompt for live mode
  echo "Do you want to enter live mode? (yes/no)"
  read USER_RESPONSE
  if [[ $USER_RESPONSE == "yes" ]]; then
    gnome-terminal &
    LIVE_TERMINAL_PID=$!
  fi

  install_tools
  download_ioc_file
  capture_traffic_live
  check_files
}

main
