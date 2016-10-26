#Setup

##Prerequesites

* Working green field OpenStack deployment (code currently based out of stable/liberty)
* The virtualenv used by glance should have Amazon boto package installed

## Components
Glance store driver: Handles glance image endpoint for AWS AMIs

## Instructions
1. Copy the glance_store/_drivers directory to <glance_store_root>/glance_store/_drivers
2. Update the configuration file -- /etc/glance/glance-api.conf
  ```
  [glance_store]
   default_store = aws
   stores = aws
  [AWS]
   secret_key = <your aws secret access key> 
   access_key = <your aws access key>
   region_name = <was region to use>
  ```
3. Restart the glance-api service
4. Populate AMI as glance image using helper script.
