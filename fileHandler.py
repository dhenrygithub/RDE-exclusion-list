import json
import csv

# Write JSON to debug file
debug_file = open(debug_name, "a")
debug_file.write(json.dumps(data, indent=2))
debug_file.write("\n\n------------------------------------------------------------------------------------\n\n")
debug_file.close()

# Open CSV
output_file = open(output_name, mode='a')
# create the csv writer object
csv_writer = csv.writer(output_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
# Write Header Rows
csv_writer.writerow(["Host",
                     "IP",
                     "Port",
                     "Grade",
                     "HTTP Status Code",
                     "HSTS Header",
                     "Cert Common Name",
                     "Cert Issuer",
                     "Cert Expires",
                     "TLS 1.1",
                     "TLS 1.2",
                     "TLS 1.3",
                     "1.1 - SSLv2",
                     "1.1 - SSLv3",
                     "1.2 - DES/3DES/RC4/NULL/Export",
                     "1.3 - MD5",
                     "1.4 - Cipher < 128 Bits",
                     "1.5 - Insecure Reneg",
                     "1.6 - Cert Key Size < 2048 Bits",
                     "1.7 - MD5/SHA1 Signed Certs",
                     "1.8 - Expired Certs",
                     "1.9 - TLS 1.0",
                     "4.1 - Cert Not Trusted By Default",
                     "5.1 - Invalid HSTS Header",
                     "X-Frame-Options",
                     "X-Powered-By",
                     "Server",
                     "X-AspNetMvc-Version",
                     "Bluecoat Error",
                     "Need Followup?",
                     "Notes"])
output_file.close()

# Open CSV
analyze_output_file = open(output_name, mode='a')
# create the csv writer object
analyze_csv_writer = csv.writer(analyze_output_file, delimiter=',', quotechar='"',
                                quoting=csv.QUOTE_MINIMAL)
# create the csv writer object
analyze_csv_writer.writerow([data['host'],
                             data['endpoints'][endpoint]['ipAddress'],
                             data['port'],
                             data['endpoints'][endpoint]['grade'],
                             httpStatusCode,
                             HSTS_Header,
                             data['certs'][0]['commonNames'][0],
                             data['certs'][0]['issuerSubject'],
                             datetime.datetime.fromtimestamp(int(cert_expires)),
                             TLS11,
                             TLS12,
                             TLS13,
                             SSL2,
                             SSL3,
                             OGW_Ciphers,
                             OGW_MD5,
                             OGW_Cipher_Strength,
                             OGW_Reneg_Support,
                             OGW_Key_Size,
                             OGW_Cert_Alg,
                             OGW_Cert_Expired,
                             TLS1,
                             OGW_Cert_Trust,
                             OGW_HSTS,
                             Frame_Options_Value,
                             Powered_By,
                             Server,
                             AspNetMvc,
                             Bluecoat_Gateway_Error,
                             Follow_Up,
                             ])
analyze_output_file.close()