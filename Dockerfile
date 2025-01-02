FROM mitmproxy/mitmproxy:latest

# Working directory
WORKDIR /home/mitmproxy/.mitmproxy

# run CMD
CMD ["mitmdump", "-s", "/home/mitmproxy/.mitmproxy/traffic_logger.py"]