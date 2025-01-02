import os, re, uuid, json, datetime
from urllib.parse import unquote

forbidden_chars = re.compile("[^\\w\\-\\.]")

class TrafficLogger:
    def __init__(self):
        self.output_directory = "~/.mitmproxy/log/"
        self.ensure_directory_exists(self.output_directory)
        self.log_file = open(os.path.join(self.output_directory, "mitmproxy.log"), "a")

    def ensure_directory_exists(self, directory):
        if not os.path.exists(directory):
            os.makedirs(directory)

    def makedirs(self, directory):
        head,tail = os.path.split(directory)
        if not os.path.isdir(head):
            head = self.makedirs(head)
            directory = os.path.join(head,tail)
        if(os.path.isfile(directory)): #our special case - rename current dir
            tail += "[dir]"
            directory = os.path.join(head,tail)
            return self.makedirs(directory)
        if(not os.path.isdir(directory)):
            os.mkdir(directory)  
        return directory

    def dump(self, flow, attr, random_id):
        message = getattr(flow, attr)

        #Don't dump empty messages
        if(len(message.content) == 0):
            return
        
        #get host directory name and path directories string
        host = flow.request.host
        if flow.request.port != 80:
            host += "-"+str(flow.request.port)
        pathstr = unquote(
            flow.request.path
                .split("#")[0] #remove hash
                .split("?")[0] #remove queryString
            )
        pathstr = os.path.normpath(pathstr).lstrip("./\\")
        if os.path.basename(pathstr) == "":
            pathstr += "__root__"

        host = host.lstrip("./\\")
        if host == "":
            host = "invalid-host"

        dirty_path = [host] + pathstr.replace("\\","/").split("/")
        path = []
        for pathelem in dirty_path:

            #replace invalid characters with placeholder
            #(don't remove, that could reintroduce relative path changes)
            pathelem = forbidden_chars.sub('_', pathelem)

            #cut off length
            if len(pathelem) >= 35:
                pathelem = pathelem[:15] + "[..]" + pathelem[15:]

            path.append(pathelem)

        #If our path is too long, remove directories in the middle
        dirRemoved = False
        while sum(len(s) for s in path) > 150:
            del path[ len(path) / 2 ]
            dirRemoved = True
        # Add placeholder directory if we removed at least one directory
        if dirRemoved:
            splitpos = (len(path)+1) / 2
            path = path[:splitpos] + ["[...]"] + path[splitpos:]

        filename = os.path.join(self.output_directory,*path)

        d, filename = os.path.split(filename)
        filename = os.path.join(self.makedirs(d),filename)

        content = message.content

        #If filename is a directory, rename it.
        if(os.path.isdir(filename)):
            os.rename(filename, filename+"[dir]")

        #Rename if file already exists and content is different
        filename, ext = os.path.splitext(filename)
        appendix = ""
        if attr == "request":
            filename += " (request)"
        while(os.path.isfile(filename+str(appendix)+ext)):
            if os.path.getsize(filename+str(appendix)+ext) == len(content):
                with open(filename+str(appendix)+ext,"rb") as f:
                    if(f.read() == content):
                        return
            if(appendix == ""):
                appendix = 1
            else:
                appendix += 1
        filename = filename + str(appendix) + random_id + ext

        #self.log_file.write(f"Dumping {attr} to {filename}\n")
        with open(filename, 'wb') as f:
            f.write(content)
        
        return filename

    def response(self, flow):
        random_id = str(uuid.uuid4())
        jsonObject = {
            "ID": random_id,
            "request": {
                "_timestamp": flow.request.timestamp_start,
                "timestamp": datetime.datetime.fromtimestamp(flow.request.timestamp_start, tz=datetime.timezone.utc).isoformat(),
                "ip": flow.client_conn.address,
                "method": flow.request.method,
                "url": flow.request.url,
                "headers": dict(flow.request.headers),
                "filename": self.dump(flow, "request", random_id)
            }#,
            # "response": {
            #     "ip": flow.server_conn.address,
            #     "status_code": flow.response.status_code,
            #     "headers": dict(flow.response.headers),
            #     "filename": self.dump(flow, "response", random_id)
            # }
        }
        self.log_file.write(json.dumps(jsonObject, indent=10))
        self.log_file.flush()

    def done(self):
        self.log_file.close()

addons = [
    TrafficLogger()
]
