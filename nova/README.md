## Setup

### Prerequesites
1. Working green field OpenStack deployment (code currently based out of stable/liberty)
2. The virtualenv used by nova should have Amazon boto package installed

#### Components
- Nova driver: Handles instance creation, power operations and snapshotting an instance to AMI

### Instructions
1. Copy the nova/ec2 directory to <nova-root>/nova/nova/virt/
2. Update the configuration files - 
    1. edit /etc/nova/**nova.conf** 
    ```
    [DEFAULT]
    compute_driver = ec2.EC2Driver
    
    [AWS]
    secret_key = <your aws secret access key>
    access_key = <your aws access key>
    region_name = <was region to use>
    ```
3. Restart the nova compute services
