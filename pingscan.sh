#!/bin/bash

# Define the range of IP addresses
start_ip="X.X.X.X"
end_ip="Y.Y.Y.Y"

# Convert IP addresses to their integer equivalents for easier iteration
ip_to_int() {
  local a b c d
  IFS=. read -r a b c d <<< "$1"
  echo $(((a << 24) + (b << 16) + (c << 8) + d))
}

int_to_ip() {
  local ip=$1
  echo "$(( (ip >> 24) & 255 )).$(( (ip >> 16) & 255 )).$(( (ip >> 8) & 255 )).$(( ip & 255 ))"
}

start_int=$(ip_to_int $start_ip)
end_int=$(ip_to_int $end_ip)

# Output file
output_file="responsive_ips.txt"
> $output_file

# Iterate over the IP range
for ((i=start_int; i<=end_int; i++)); do
  ip=$(int_to_ip $i)
  echo "Pinging $ip..."
  if ping -c 2 -W 2 $ip; then
    echo "$ip is responsive."
    echo "$ip" >> $output_file
  else
    echo "$ip is not responsive."
  fi
  sleep 2
done

echo "Ping scan completed. Responsive IPs saved to $output_file."
