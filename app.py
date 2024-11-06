from scapy.all import *
import socket
import streamlit as st
import geocoder
import folium
from streamlit_folium import st_folium, folium_static
import nmap


def get_loc(ip):
    g = geocoder.ip(ip)
    addr = g.latlng

    myMap = folium.Map(location=addr, zoom_start=12)
    folium.Marker(addr, popup="My Location").add_to(myMap)
    folium.CircleMarker(addr, radius=50, color='red', fill_color='red').add_to(myMap)
    return addr, myMap

def packet(count):
    pack = ""
    packets = sniff(count = count)
    for packet in packets:
        st.write(str(packet))
    return pack

def banner_grabber(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((target, port))
        banner = s.recv(1024)
        return banner.decode().strip()
    except Exception as e:
        return str(e)
    finally:
        s.close()

def scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='sS')
    for host in nm.all_hosts():
        mac = nm[host].hostname()
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                state = nm[host][proto][port]['state']
                service = nm[host][proto][port]['name']
                product = nm[host][proto][port]['product']
                version = nm[host][proto][port]['version']
                extrainfo = nm[host][proto][port]['extrainfo']

                return '### Target : %s\n**hostname** : %s\n**Protocol** : %s\n**port** : %s\t**state** : %s\t**service** : %s\t**product** : %s\t**version** : %s\t**extrainfo** : %s' % (host, mac, proto, port, state, service, product, version, extrainfo)
                # st.write(f"Target : {host}\nhostname : {mac}\nProtocol : {proto}\nport : {port}\tstate : {state}\tservice : {service}\tproduct : {product}\tversion : {version}\textrainfo : {extrainfo}")
                # return ""


st.set_page_config(
    page_title="Network Security Toolkit",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed",
    menu_items={"Report a bug": "mailto:rohan.nayakanti@gmail.com"}
)

st.title("Network Security Toolkit")

with st.sidebar:
    st.write("Welcome to the Network Security Toolkit! This toolkit is designed to help you with network security tasks such as scanning, banner grabbing, geolocation, WiFi scanning, and packet sniffing.")
    selection = st.selectbox("Select a tool:", ["Home", "Nmap Scan", "Banner Grabber", "Geolocation", "Packet Sniffer"])
    st.write("Please select a tool from the sidebar to get started.")
    st.write("If you encounter any issues, please report them by clicking on the 'Report a bug' link in the sidebar.")
    url = st.text_input("Enter a Url", key="url")
    but = st.button("Find IP")
    if but:
        ip = socket.gethostbyname(url)
        st.write(f"The IP address of {url} is {ip}")


if selection == "Home":
    st.write("Welcome to the Network Security Toolkit! This toolkit is designed to help you with network security tasks such as scanning, banner grabbing, geolocation, WiFi scanning, and packet sniffing.")
    st.write("Please select a tool from the sidebar to get started.")

elif selection == "Nmap Scan":
    st.subheader("Nmap Scan", divider="rainbow")
    choice = st.selectbox("Select an option:", ["Domain Name", "IP Address"], key="choice")
    if choice == "Domain Name":
        domain = st.text_input("Enter the domain name:", key="domain_name")
        target = socket.gethostbyname(domain)
    elif choice == "IP Address":
        target = st.text_input("Enter the IP address:", key="ip_address")
    
    button = st.button("Scan")
    if button:
        with st.spinner("Scanning..."):
            st.markdown(scan(target))

elif selection == "Banner Grabber":
    st.subheader("Banner Grabber", divider="rainbow")
    col1, col2 = st.columns(2)
    with col1:
        domain = st.text_input("Enter the domain name", key="domain_name1")
        target = socket.gethostbyname(domain)
        port = st.number_input("Enter the port number:", key="port_number1")
    with col2:
        target = st.text_input("Enter the IP address:", key="ip_address1")
        port = st.number_input("Enter the port number:", key="port_number2")
    button = st.button("Grab banner")
    if button:
        with st.spinner("Grabbing banner..."):
            st.write(banner_grabber.banner_grabber(target, int(port)))

elif selection == "Geolocation":
    st.subheader("Geolocation", divider="rainbow")
    choice = st.selectbox("Select an option:", ["Domain Name", "IP Address"], key="choice")
    if choice == "Domain Name":
        domain = st.text_input("Enter the domain name:", key="domain_name2")
        target = socket.gethostbyname(domain)
    elif choice == "IP Address":
        target = st.text_input("Enter the IP address:", key="ip_address2")
    
    button = st.button("Get location")
    if button:
        with st.spinner("Getting location..."):
            myaddress, myMap = get_loc(target)
            st.write(f"Latitude: {myaddress[0]} Longitude: {myaddress[1]}")
            st_data = folium_static(myMap, width=700, height=500)

            file = myMap.save("map.html")
            with open("map.html", "r") as f:
                st.download_button(
                    label="Download map",
                    data=f,
                    file_name="map.html"
                )

elif selection == "Packet Sniffer":
    st.subheader("Packet Sniffer", divider="rainbow")
    count = st.number_input("Enter the number of packets to sniff:", key="packet_count")
    button = st.button("Start sniffing")
    if button:
        with st.spinner("Sniffing packets..."):
            packet(count)
        
        
