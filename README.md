# Secure-Channel
CA Server based on RSA provided by Node-Forge.
The web server is handled by Express.

## CA Server Installation
To run the CA Server, make sure **NodeJS** and **NPM** are installed on your system.
```bash
git clone https://github.com/catalincd/Secure-Channel
cd ca-server
npm install
npm run start
```
The server should now run on port `7017`. The certificate transfer is ran through a web server, which can be accessed through a designated IP address or locally through localhost. The following examples were ran locally, please replace `localhost` with your IP and port number if running remotely.

### Issuing a certificate
To issue a certificate, provide `commonName`, `organization` and `country`. 

```bash
curl --request POST \
  --url http://localhost:7017/issue-certificate \
  --header 'Content-Type: application/json' \
  --header 'User-Agent: insomnia/10.3.0' \
  --data '{
	"commonName": "Secure-Channel-App",
	"organization": "WUT", 
	"country": "RO"
}'
```
The response data is formatted in JSON, with the received data in a **PEM** format:
```json
{
	"message": "Certificate issued successfully.",
	"certificate": "...",
	"privateKey": "..."
}
```

### Verifying a certificate
To issue a certificate, provide the certificate **PEM**  data: 
```bash
curl --request POST \
  --url http://localhost:7017/verify-certificate \
  --header 'Content-Type: application/json' \
  --header 'User-Agent: insomnia/10.3.0' \
  --data '{
	"certificate": "-----BEGIN CERTIFICATE----- ..."
}'
```
The response data is formatted in JSON, with a boolean `valid` and a detailed `reason`:
```json
{
	"valid": false,
	"reason": "Revoked certificate."
}
```

### Revoking a certificate
To revoke a certificate, provide the certificate **PEM** data and the **Private Key**: 
```bash
curl --request POST \
  --url http://localhost:7017/revoke-certificate \
  --header 'Content-Type: application/json' \
  --header 'User-Agent: insomnia/10.3.0' \
  --data '{
    "certificate": "-----BEGIN CERTIFICATE----- ..."
    "privateKey": "-----BEGIN RSA PRIVATE KEY----- ..."
}'
```
The response data is formatted in JSON, with a boolean `valid` and a detailed `reason`:
```json
{
	"valid": true,
	"message": "Certificate revoked successfully."
}
```

### Renewing a certificate
To revoke a certificate, provide the certificate **PEM** data and the **Private Key**: 
```bash
curl --request POST \
  --url http://localhost:7017/renew-certificate \
  --header 'Content-Type: application/json' \
  --header 'User-Agent: insomnia/10.3.0' \
  --data '{
    "certificate": "-----BEGIN CERTIFICATE----- ..."
    "privateKey": "-----BEGIN RSA PRIVATE KEY----- ..."
}'
```
The response data is formatted in JSON, with a boolean `valid` and a detailed `reason`:
```json
{
	"valid": true,
	"message": "Certificate renewed successfully.",
	"certificate": "-----BEGIN CERTIFICATE----- ...",
	"privateKey": "-----BEGIN RSA PRIVATE KEY----- ..."
}
```
If valid, the new `certificate` and `privateKey` are provided. The old certificate is still available until it expires, but it can be revoked without revoking the new one.


# Example Usage

Run the CA Server:
```bash
cd ca-server
npm run start
```

Run the Example Server:
```bash
cd example-server
npm run start
```

Run the Client Server:
```bash
cd example-client
npm run start
```