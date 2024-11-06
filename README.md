# Network Security Toolkit with Streamlit

This is a Streamlit application that provides a network security toolkit with several features:

1. Nmap Scan: Allows users to scan a domain name or IP address using Nmap.
2. Banner Grabber: Allows users to grab the banner of a target domain name or IP address.
3. Geolocation: Allows users to determine the geolocation of a target domain name or IP address.
4. Packet Sniffer: Allows users to capture and display a specified number of packets from a network interface.

The application uses various libraries, including:

* `scapy` for packet sniffing and manipulation
* `socket` for networking operations
* `geocoder` for geolocation services
* `folium` for mapping and visualization
* `nmap` for network scanning
* `streamlit` for building and serving the application

The application has a sidebar menu that allows users to select which tool to use. Each tool has its own set of input fields and buttons for submitting requests. The application also provides some basic error handling and feedback messages for each tool.


