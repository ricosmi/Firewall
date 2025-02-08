# Firewall
A Firewall based on OSI Layer 3, 4 and 7 protocol inspection

This is a network traffic monitoring and filtering application that analyzes packets at the application layer (Layer 7 OSI). The program allows users to view, filter and control network traffic in real time, providing advanced functionality for analyzing protocols such as IP, TCP, UDP, ICMP, HTTP, DNS and SSH.

The application is built in Python and uses raw sockets for packet capture, along with a CustomTkinter-based GUI system for an intuitive experience. The firewall implements two main filtering mechanisms:
-Passive filtering, which allows users to view only packets that meet certain conditions based on fields in protocol headers.
-Active filtering, which provides the ability to accept or block packets according to manually defined rules.
Features of the application include advanced search and filtering system, visual highlighting of packets according to their status (accepted, blocked), as well as extensibility to include new protocols and traffic analysis methods.

This project is useful for those who want to better understand network security and traffic filtering mechanisms. In the future, it could be extended to include support for encrypted traffic analysis (HTTPS) or integration with an automatic attack detection system based on machine learning.
