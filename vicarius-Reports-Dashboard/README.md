# Vicarius-vRx-Reports-Dashboard

Tested on Ubuntu Server 22.04 LTS

# VicariusVrxReports Setup Instructions

## Prerequisites 

### Virtual Machine 
A virtual machine is recommended to install the vRx Reports Dashboard. 

#### Sizing Recommendations 
Sizing recommendations are based on the number of assets in your dashboard. 
 * Less than 500 assets
   * 2 Core CPU - 4 GB Ram - 20 GB Disk
 * 500 to 1000 assets
   * 2 Core CPU - 8 GB Ram - 30 GB Disk
 * Over 1000 assets
   * 4 Core CPU - 12 GB Ram - 50 GB Disk    

#### OS Recommendations
  * Ubuntu 22.04 has been thoroughly tested
  * Any OS that supports Bash scripting and Docker

### Set the timezone on the VM to your timezone.

### Review the following KB article to create a new API Key from your Vrx Dashboard
https://customer-portal.vicarius.io/getting-started-with-vrx-rest-api

### Your dashboard_id corresponds to the url you use to login to your dashboard
Example: organization in https://organization.vicarius.cloud/

# Installation Method 
## Method 1: URL Download

### Download and unzip the file
Download the package to the asset that will host the docker containers
vRxReportsDashboard.tar.gz https://github.com/VicariusInc/vRx-Public-Resources/releases/latest/download/vicarius-vrx-reports.tar.gz


Newest Version
```bash
mkdir vicarius-vrx-reports-dashboard
cd vicarius-vrx-reports-dashboard
wget https://github.com/VicariusInc/vRx-Public-Resources/releases/latest/download/vicarius-vrx-reports.tar.gz
tar -xvzf vicarius-vrx-reports.tar.gz
```


### Install Docker and configure the containers
Install the Docker stack using the installDocker.sh script:

```bash
sudo chmod +x installDocker.sh
sudo ./installDocker.sh
```

### Initialize Docker Secrets 
Create docker secrets to stor your dashboard_id, api_key, postgres_user, postgres_password

```bash
sudo chmod +x initDocker.sh
sudo ./initDocker.sh
```
Copy your api key from the vRx dashboard 
- Login into your dashboard
- go to Settings - Integrations - Installed Integrations - API
- Click on the API and copy the API Key
- ![API](https://github.com/VicariusInc/vRx-Public-Resources/assets/115802071/b14ee8a5-c8e2-46f0-a8e1-37be4520d4de)



Your dashboard_ID is the first portion of your dashboard url 
- https://example.vicarius.cloud, Dashboard_id is example
- ![dbname](https://github.com/VicariusInc/vRx-Public-Resources/assets/115802071/321048fc-a642-4143-96d1-7c58ddd01188)


Create the password for the local Database. This user will be used to access the database by data visualization tools. Please keep the username and password in a safe place

Optional Tools:
Specify Which Optional Tools you would like to be installed. 
- Metabase: Data Visualization with Template
- ![metabase](https://github.com/VicariusInc/vRx-Public-Resources/assets/115802071/41f3074a-8175-44d1-a950-6926dea4ae6f)



### Bulid and push Docker images to Registry 
Deploy the Docker stack using the buildPushDocker.sh script:
```bash
sudo chmod +x buildPushDocker.sh
sudo ./buildPushDocker.sh
```

### Deploy Containers 
Deploy the Docker stack using the redeployDocker.sh script:
```bash
sudo chmod +x redeployDocker.sh
sudo ./redeployDocker.sh
```

* Running the redeployDocker.sh script will overwrite any existing application database. To update the docker image and keep the database intact use updateDocker.sh


# Confrim the Deployment

Run docker ps to confirm the containers are up.
```bash
sudo docker ps
```
![dockerps](https://github.com/VicariusInc/vRx-Public-Resources/assets/115802071/f23bafc4-0250-4067-aac4-9d8d0e7ebd8f)



# Optional Tools

## Apache SuperSet
Coming soon...

## Metabase
https://www.metabase.com/
https://www.metabase.com/start/oss/
https://www.metabase.com/license/
Metabase is an open-source business intelligence platform. You can use Metabase to ask questions about your data, or embed Metabase in your app to let your customers explore their data on their own.

* It is recommended to let the app complete the initialization and first run before launching metabase. 
* The initial run can take several hours depending on the size of your data.
* A progress bar is planned 

### Install Metabase

To install Metabase run the metabaseInstall.sh script.
```bash
sudo chmod +x optional-metabaseInstall.sh
sudo ./optional-metabaseInstall.sh
 ```
### Check that Metabase is running

Metabase Docker Service 
```bash
sudo docker service ls
 ```
- ![metabasels](https://github.com/VicariusInc/vRx-Public-Resources/assets/115802071/322c27cc-6ba6-4775-b027-2425a867bc43)


Metabase Docker Container
```bash
sudo docker ps
 ```
- ![metabasels2](https://github.com/VicariusInc/vRx-Public-Resources/assets/115802071/e97b8c63-c39f-450a-8dc9-84c0b368b460)

### Configure Metabase
Navigate to Metabase installation in a web browser 
- > http://your_host:4000

The Metabase installation installs a template by default. When you navigate to the your installation you will receive a login page. Please log in using the default credentials 
* The Login prompt can take some time to appear depending how much data needs to be pulled into the local database from vRx.


- Default Username: vrxadmin@vrxadmin.com
- Default Password: Vicarius123!@#

Once Logged in go to settings account settings and change the default password 
- ![mbaccountsettings](https://github.com/VicariusInc/vRx-Public-Resources/assets/115802071/c0a789fe-8b32-4179-9054-548b68861e20)



After changing the default credentials, Change the database settings to reflect the database user and password created earlier.

- Go to Settings - Admin Settings - Selecte Database on the top navigation window
-![mbdatabse](https://github.com/VicariusInc/vRx-Public-Resources/assets/115802071/14375fae-89e0-4136-b0d0-dafc82397076)
- Select the vRX-Reports database
- Change the following settings
  - Database Name: Your dashboard name
  - Username: Database user created earlier
  - Passowrd: Database password created earlier
- Save Changes

## Portainer CE
https://docs.portainer.io/start/install-ce
Portainer Community Edition (CE) is our foundation. With over half a million regular users, CE is a powerful, open source toolset that allows you to easily build and manage containers in Docker, Docker Swarm, Kubernetes and Azure ACI.

To install Portainer run the portainerInstall.sh script.
```bash
sudo chmod +x portainerInstall.sh
sudo ./portainerInstall.sh
 ```

---

**Additional Notes:**
- Ensure your Docker and Docker Compose versions support `version: '3.7'` as specified in `docker-compose.yml`.
- Adjust volume paths in `docker-compose.yml` as needed based on your directory structure.
- Verify that `entrypoint.sh` and `crontab` are correctly configured for your application.

