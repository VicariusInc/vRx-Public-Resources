import pip
import socket
import logging
import os

# online check module
def isOpen(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((ip, int(port)))
        s.shutdown(2)
        return True
    except:
        return False


# logging configurations
logging.basicConfig(filename="LinuxPush.log", format='%(asctime)s %(levelname)-8s %(message)s', level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S')
logging.info("###################################")
logging.info("####Starting Remote Push Script####")
logging.info("###################################")

# running the module checks
logging.info("Trying to import SSH tools, if they doesnt exists - install them...")
try:
    import paramiko
    logging.info("paramiko imported successfully")
except ImportError:
    logging.warning("module not exists. trying to download and install it...")
    pip.main(['install', 'paramiko'])
    import paramiko

logging.info("Trying to import Python requst, if they doesnt exists - install them...")
try:
    import requests
    logging.info("requests imported successfully")
except ImportError:
    logging.warning("module not exists. trying to download and install it...")
    pip.main(['install', 'requests'])
    import requests

# yaml tools are a bit different from last package since the module name and import name are different
logging.info("Trying to import yaml tools, if they doesnt exists - install them...")
try:
    import yaml
except:
    pip.main(['install', 'pyyaml'])
    import yaml


# reading the yaml file
logging.info("Trying to read the yaml file")
with open(r'LinuxPush.yaml') as file:
    try:
        yaml_file = yaml.safe_load(file)
    except yaml.YAMLError as exception:
        logging.error("Error reading the YAML file: " + exception)
        quit(1)


# checking if endpoint tags are needed in the command
logging.info("Checking if there are any Endpoint Tags")
tags = ""
if "EndpointTag" in yaml_file:
    tags += "/EndpointTag="
    if len(yaml_file["EndpointTag"]) > 1:
        for x in yaml_file["EndpointTag"]:
            tags += x
            tags += ","
        tags = tags[:-1]
    else:
        for x in yaml_file["EndpointTag"]:
            tags += x
else:
    logging.info("No Endpoint Tags found")


# Checking if proxy is needed in the command
if "Proxy" in yaml_file:
    proxy = yaml_file['Proxy']
    logging.info("Proxy added")
else:
    logging.info("No Proxy found")


# preparing the SSH install command
ssh_command = 'sudo -k /tmp/Topia.sh /SecretKey=' + yaml_file['SecretKey'] + ' /Hostname=' + yaml_file['Hostname'] + ' /AgentType=' + yaml_file['AgentType'] + " " + tags
if 'proxy' in globals():
    ssh_command = ssh_command + " /ProxyAddress=" + proxy


# checking if the Topia.sh file exists
if not os.path.exists("Topia.sh"):
    logging.warning("Cannot find Topia.sh at the executed folder. trying to download from S3")
    req = requests.get("https://vicarius-installer.s3.amazonaws.com/Topia.sh",allow_redirects=True)
    open("Topia.sh", "wb").write(req.content)
    if not os.path.exists("Topia.sh"):
        logging.error("Cannot find Topia.sh file or download it.")
        quit(1)
    logging.info("Topia.sh downloaded from S3")

# loading host.list
logging.info("Reading hosts file...")
try:
    fileobj = open("hosts.list")
except:
    logging.error("Error reading hosts.list. Verify the file exists")
    quit(1)
lines = fileobj.read().split('\n')
counter = str((len(lines)))
logging.info(counter + " host(s) found")

# checking port 22 on each host in host.list
hosts = []
logging.info("Checking port 22 on the destination hosts...")
for line in lines:
    infos = line.split(",")    
    if isOpen(infos[0], "22"):
        logging.info("Host " + infos[0] + " is listening on port 22")
        hosts.append(line)
    else:
        logging.warning("Host " + infos[0] + " is NOT available on port 22. Ignoring it...")


# setting SSH configurations
ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# starting to work on each host (excluding those who don't listen port 22)
for infos in hosts:
    logging.info("Getting username and password")
    
    info = infos.split(",")
    host = info[0]
    username = info[1]
    pwd = info[2]

    # setting SSH connection
    logging.info("Trying to SSH " + host)
    try:
        ssh_client.connect(hostname=host,username=username,password=pwd)
    except paramiko.SSHException:
        logging.error("SSH to " + host + " was not successful. Skipping to the next host")
        continue
    # check if topia installed
    stdin, stdout, stderr = ssh_client.exec_command('sudo -k ls /usr/share/vicarius',get_pty=True)
    stdin.write('{}\n'.format(pwd))
    stdin.flush()

    installed = True
    for line in stdout.read().splitlines():
        logging.info('host: %s: %s' % (host, line)) 
        if "No such file or directory" in str(line):
            installed = False
            break
        if "No existe el archivo o el directorio" in str(line):
            installed = False
            break

    if installed == True:
        logging.error(host + ' seems to have topia installed. Run the uninstall script & try again')
        continue

    # copy the file to the linux machine
    logging.info("Copying the installation file to " + host)
    sftp_client = ssh_client.open_sftp()
    try:
        sftp_client.put('Topia.sh',"/tmp/Topia.sh")
    except:
        logging.error('Something went wrong coping Topia.sh to ' + host + '. Moving to next host')
        continue
    # running the installation on the remote machine
    logging.info('Installation file copy successful')
    logging.info('Adding execution permission on the destination file')
    stdin, stdout, stderr = ssh_client.exec_command('sudo -k chmod +x /tmp/Topia.sh', get_pty=True)
    stdin.write('{}\n'.format(pwd))
    stdin.flush() 
    for line in stdout.read().splitlines():
        logging.info('host: %s: %s' % (host, line))   
    logging.info('Starting the installation')
    stdin, stdout, stderr = ssh_client.exec_command(ssh_command, get_pty=True)
    stdin.write('{}\n'.format(pwd))
    stdin.flush()
    for line in stdout.read().splitlines():
        logging.info('host: %s: %s' % (host, line))
    # checking if topia folder created after installation
    logging.info('Checking if Topia folder available')
    stdin, stdout, stderr = ssh_client.exec_command('ls /usr/share/vicarius')
    if stdout == '':
        logging.error('Installation finished on host ' + host + ' but cant find Topia folder')
        continue
    # Logging out of the host
    logging.info('Logging out of host ' + host)
    sftp_client.close()
    ssh_client.close()


logging.info("Linux Push Installation script ended.")