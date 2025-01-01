###DNS CLient

`client-final.py` is a program that fetches the host IP address of the given domain name and sends a HTTP 1.1 request for the index page of the website to the fetched IP address. The current code in the program fetches the ip address of tmz.com but you can change it to any domain name you wish. Just make sure to change the domain name
in the code lines `query = create_query("tmz.com", TYPE_A)` and `client_tcp.sendall(b"GET / HTTP/1.1\r\nHost:tmz.com\r\n\r\n")`
