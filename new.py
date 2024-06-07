import ssl
import socket
import datetime
import json

def check_ssl_certificate(domain, record_id):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = cert.get('issuer', '')
                common_name = [x[0][1] for x in issuer if x[0][0] == 'commonName']
                not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

                if common_name and any(cn in common_name[0] for cn in ["R3", "ISRG Root", "cPanel"]):
                    status = "This certificate is issued by Lets Encrypt" if "R3" in common_name[0] or "ISRG Root" in common_name[0] else "Cpanel Temporary SSL"
                else:
                    status = "Website has Paid SSL installed"

                result = {
                    "id": str(record_id),
                    "domain": domain,
                    "issuer": common_name[0] if common_name else "N/A",
                    "issued_to": cert["subject"][0][0][1],
                    "issued_by": cert["issuer"][0][0][1],
                    "valid_From": not_before.strftime('%Y-%m-%d'),
                    "valid_Until": not_after.strftime('%Y-%m-%d'),
                    "status": status,
                    "status_two": ""
                }
                return result
    except Exception as e:
        result = {
            "id": str(record_id),
            "domain": domain,
            "issuer": "N/A",
            "issued_to": "N/A",
            "issued_by": "N/A",
            "valid_From": "N/A",
            "valid_Until": "N/A",
            "status": "Website has SSL Expired",
            "status_two": f"Error checking SSL certificate for {domain}: {e}"
        }
        return result

# List of domains to check
domains = []
fileOB = open('example_data.txt', 'r')
lines = fileOB.read().splitlines()
fileOB.close()

for line in lines:
    domains.extend(line.split())

results = []
record_id = 1
for domain in domains:
    result = check_ssl_certificate(domain, record_id)
    results.append(result)
    record_id += 1

# Print results as JavaScript export
print("export const freshInfo = ", end="")
print(json.dumps(results, indent=4))