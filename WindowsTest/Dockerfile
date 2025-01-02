FROM mcr.microsoft.com/windows/server:ltsc2022

# Define the working directory
WORKDIR C:/app

# Copy the application files
COPY mitmproxy-ca-cert.cer .

RUN certutil -addstore -f "Root" mitmproxy-ca-cert.cer

# Run powershell command
#CMD ["Invoke-WebRequest -Uri 'http://192.168.10.130:8088' -Proxy 'http://172.17.0.2:8080' -Method Post -InFile .\Win10.xml"]