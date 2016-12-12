## Setup

Updated: 12th December 2016
         (Updated to be in sync with Platform9 release 2.4)

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
    max_cpus = <maximum CPUs that nova should use (default: 500)>
    max_memory_mb = <maximum memory that nova should use (default: 102400 i.e. 1000GB)>
    max_disk_gb = <maximum storage that nova should use (default: 1024 i.e. 1 TB)>
    ```
3. Restart the nova compute services

### Running unit tests:
1. Copy the nova/tests/ec2 to <nova-root>/nova/tests/unit/virt directory
2. To run the AWS Driver unit tests -
    ```
    tox -e <env> nova.tests.unit.virt.ec2
    e.g. to run python 2.7 tests -
    tox -e py27 nova.tests.unit.virt.ec2
    ```
