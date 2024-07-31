# Step 5: Build Docker images for each service and push to the local registry


# Building the db service Docker image and pushing to local registry
echo "Building the db service Docker image..."
docker build -t localhost:5000/vrx-reports-appdb:latest ./appdb
echo "Pushing the db service Docker image to local registry..."
docker push localhost:5000/vrx-reports-appdb:latest

# Building the app service Docker image and pushing to local registry
echo "Building the app service Docker image..."
docker build -t localhost:5000/vrx-reports-app:latest ./app
echo "Pushing the app service Docker image to local registry..."
docker push localhost:5000/vrx-reports-app:latest


# Building the app service Docker image and pushing to local registry
echo "Building the webapp service Docker image..."
docker build -t localhost:5000/vrx-reports-web:latest ./webapp/mgntDash
echo "Pushing the webapp service Docker image to local registry..."
docker push localhost:5000/vrx-reports-web:latest