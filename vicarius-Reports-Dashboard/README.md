# vAnalyzer



# vAnalyzer Setup Instructions

### Prerequisites

Tested on Ubuntu Server 22.04 LTS

#### Virtual Machine
A virtual machine is recommended for this installation. Ensure you have allocated sufficient resources based on the number of assets in your dashboard.

**Sizing Recommendations:**
- Less than 500 assets: 2 Core CPU, 4 GB RAM, 20 GB Disk
- 500 to 1000 assets: 2 Core CPU, 8 GB RAM, 30 GB Disk
- Over 1000 assets: 4 Core CPU, 12 GB RAM, 50 GB Disk

#### OS Recommendations
Ubuntu 22.04 is recommended and has been thoroughly tested. Other OSes that support Bash scripting and Docker are also compatible.

### Step-by-Step Installation Method

#### Step 1: Download and Unzip the File
Download the package to the asset that will host the Docker containers:

```bash
mkdir vAnalyzer
cd vAnalyzer
wget https://github.com/VicariusInc/vRx-Public-Resources/releases/latest/download/vicarius-vrx-reports.tar.gz
tar -xvzf vicarius-vrx-reports.tar.gz
```

#### Step 2: Install Docker and Configure the Containers
Install the Docker stack using the `installDocker.sh` script:

```bash
sudo chmod +x installDocker.sh
sudo ./installDocker.sh
```

#### Step 3: Initialize Docker Secrets
Create Docker secrets to store your dashboard_id, api_key, postgres_user, and postgres_password.

```bash
sudo chmod +x initDocker.sh
sudo ./initDocker.sh
```
Follow the prompts to enter your 
 * API key (obtained from vRx dashboard)
 * Dashboard ID (dashboard_id.vicarius.cloud)
 * PostgreSQL user 
 * Password 
 * Optionally specify any additional tools you want to install like Metabase. ![image](https://github.com/user-attachments/assets/1977a467-7db5-42a4-ad1e-a20fbb20e693)


##### Copy your api key from the vRx dashboard 

- Login into your dashboard
- go to Settings - Integrations - Installed Integrations - API
- Click on the API and copy the API Key

![image](https://github.com/user-attachments/assets/25ebe66a-7eeb-4e0e-a2e3-32c22d032517)



##### Your dashboard_ID is the first portion of your dashboard url 
- https://example.vicarius.cloud, Dashboard_id is example

![image](https://github.com/user-attachments/assets/84302dfc-10c6-43e2-a959-ce909ac71104)

#### Step 4: Build and Push Docker Images to Registry
Deploy the Docker stack using the `buildPushDocker.sh` script:

```bash
sudo chmod +x buildPushDocker.sh
sudo ./buildPushDocker.sh
```

#### Step 5: Deploy Containers
Deploy the Docker stack using the `redeployDocker.sh` script:

```bash
sudo chmod +x redeployDocker.sh
sudo ./redeployDocker.sh
```
Note: Running this script will overwrite any existing application database. If you need to update the Docker image while keeping the database intact, use the `updateDocker.sh` script instead.

#### Step 6: Confirm the Deployment
Run `docker ps` to confirm that the containers are up and running.

```bash
sudo docker service ls 
```
![image](https://github.com/user-attachments/assets/714798b3-cbac-47c9-8942-619d1d831b4e)

You should see a list of running Docker services related to your vAnalyzer setup.


## vAnalyzer Dashboard (Metabase) 
By following these steps, you will setup and deploy the vAnalyzer on your Ubuntu Server system.

### Prerequisites

#### Licenseing
##### Metabase
https://www.metabase.com/
https://www.metabase.com/start/oss/
https://www.metabase.com/license/
Metabase is an open-source business intelligence platform licensed under AGPL. You can use Metabase to ask questions about your data, or embed Metabase in your app to let your customers explore their data on their own.

#### DNS Configuration
- **HTTPS/TLS Configuration:** Ensure you have properly configured HTTPS/TLS for secure communication if applicable.
A DNS hostname is required for this implementation. Before deployment, configure an A record to access the dashboard. The A record can be in public or private:
- If a public record is used, HTTPS will be set up with a Let's Encrypt cert automatically.
- If a private record is used, a default cert will be used.

### Install Metabase

1. **Add Hostname to Docker Compose File**

   Edit the `metabase/docker-compose.yml` file:
   ```bash
   nano metabase/docker-compose.yml
   ```
   Locate line 23 inside the labels section and add your hostname:
   ```yaml
   - "traefik.http.routers.metabase.rule=Host(`metabase.example.com`)"
   ```
![image](https://github.com/user-attachments/assets/5fe180af-340e-4cbf-95e3-84bcd9338c18)

2. **Add Your Email for Let's Encrypt Certificate (Optional)**

   Edit the `traefik/config/traefik.yaml` file:
   ```bash
   nano traefik/config/traefik.yaml
   ```
   Locate line 44 inside the `certificatesResolvers` section and replace `admin@example.com` with your email:
   ```yaml
   certificatesResolvers:
     letsencrypt:
       acme:
         email: admin@yourdomain.com
         storage: acme.json
         httpChallenge:
           entryPoint: web
   ```
![image](https://github.com/user-attachments/assets/66a58e00-1692-4bc0-93cc-2530b39ca59e)

3. **Run the Metabase Installation Script**

   Make the script executable and run it:
   ```bash
   sudo chmod +x optional-metabaseInstall.sh
   sudo ./optional-metabaseInstall.sh
   ```

### Check That Metabase is Running

1. **List Docker Services**

   Verify that the Metabase service is running:
   ```bash
   sudo docker service ls
   ```
   The containers can take 5 minutes to come online and be active.
   ![image](https://github.com/user-attachments/assets/c734283e-e266-44c6-a1dc-690448c2e38f)

2. **Navigate to Metabase Installation in a Web Browser**

   Open your web browser and go to:
   ```
   https://your_host
   ```

3. **Log In Using Default Credentials**

   - Default Username: `vrxadmin@vrxadmin.com`
   - Default Password: `Vicarius123!@#`

4. **Change the Default Password**

   Once logged in, go to:
   ```
   Settings > Account settings
   ```
   Change the default password for security reasons.
![image](https://github.com/user-attachments/assets/c44a9547-8ea8-4317-8edb-fe52634433dc)

5. **Change Database Settings**

   Go to:
   ```
   Settings > Admin Settings > Select "Database" on the top navigation window
   ```
   - Select the `vRX-Reports` database
   - Change the following settings:
     - Database Name: Your dashboard name
     - Username: The database user created earlier
     - Password: The database password created earlier
   - Save Changes
![image](https://github.com/user-attachments/assets/c4ea21bd-1dd7-416b-8f74-fbba22dba250)

### Additional Notes

- **Log View**: To check the status of the initial sync, you can view the log file:
  ```bash
  tail -n 10 app/logs/initialsync.log
  ```

- **Metabase Docker Service**: Ensure that Metabase is active and running properly using the command:
  ```bash
  sudo docker service ls
  ```

By following these steps, you will have successfully instaledl and configure Metabase as your vAnalyzer Dashboard on an Ubuntu Server system.


## Updating vAnalyzer


This process updates the `app` and `appdb` containers.
** Note: Any additional reports or custom reports will be over written by this process **

#### Step 1: Download and Unzip the File

1. **Create a New Folder**:
   ```bash
   mkdir vAnalyzer
   cd vAnalyzer
   ```
   Replace `<folder_name>` with your desired folder name.

2. **Download the Package**:
   ```bash
   wget https://github.com/VicariusInc/vRx-Public-Resources/releases/latest/download/vicarius-vrx-reports.tar.gz
   tar -xvzf vicarius-vrx-reports.tar.gz
   ```

#### Step 2: Build and Push Docker Images to Registry

1. **Make the Script Executable**:
   ```bash
   sudo chmod +x buildPushDocker.sh
   ```

2. **Run the Script**:
   ```bash
   sudo ./buildPushDocker.sh
   ```

#### Step 3: Update the Containers

1. **Make the Script Executable**:
   ```bash
   sudo chmod +x updateDocker.sh
   ```

2. **Run the Script**:
   ```bash
   sudo ./updateDocker.sh
   ```
   *Note: If you receive an error, run the command again after a few minutes.*


By following these steps, you will successfully update both the app containers and the optional web dashboad of vAnalyzer.
