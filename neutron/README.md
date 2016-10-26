## Setup

### Prerequesites
1. Working green field OpenStack deployment (code currently based out of stable/liberty)
2. No prior neutron agents. This service does not work if neutron l3 agent and ml2 drivers are already configured.

#### Components
- ML2 core plugin with AWS Mechanism Driver handles **Networks, Subnets, Ports** and **Security Groups**.
- AWS Router Service Plugin handles **Routers, Router Interfaces, Floating IPs**.

### Instructions
1. Copy files from this repo into your neutron source tree:
    1. directory neutron/plugins/ml2/drivers/aws to neutron module directory {neutron-root}/neutron/plugins/ml2/drivers/
    2. neutron/services/l3_router/aws_router_plugin.py to {neutron-root}/neutron/services/l3_router/
    3. requirements.txt and setup.cfg to your {neutron-root}
    4. the three files under neutron/common to {neutron-root}/neutron/common/
    5. neutron/plugins/ml2/managers.py to {neutron-root}/neutron/plugins/ml2/

2. Update configuration files
    1. /etc/neutron/**neutron.conf** Set the following config options:
        ```

        [DEFAULT]
        service_plugins = aws_router
        core_plugin = ml2

        [credentials]
        aws_access_key_id = <your aws access key>
        aws_secret_access_key = <your aws secret access key>
        region_name = <the region you would like to use>
        ```

    2. /etc/neutron/plugins/ml2/**ml2_conf.ini**

        ```

        [ml2]
        type_drivers = local,flat
        tenant_network_types = local
        mechanism_drivers = aws

        [ml2_type_flat]
        flat_networks = *
        ```

3. Restart neutron server service
    > service openstack-neutron-server restart

### Creating network objects in AWS

**Neutron to AWS object mapping**

|     Neutron     |        AWS       |
| --------------- | ---------------- |
|     Network     |     None         |
|     Subnet      |   VPC + subnet   |
|     Router      | Internet Gateway (IG) |
|     Ports       |     None         |

**Operations**

|     Neutron     |        AWS       |
| --------------- | ---------------- |
| Create Network  |     None         |
| Create Subnet with < /16 |  Create VPC with /16 + subnet with given CIDR |
| Create router   |  Create Internet Gateway |
| Attach gateway  | None |
| Attach interface to router | Add VPC to the IG |
| Create Floating IP | Create Elastic IP |
| Associate FIP to an instance | Associate Elastic IP to instance |
| Delete FIP | Delete elastic IP |
| Delete subnet | Delete subnet within the VPC. Delete VPC if last subnet |
| Delete Network | None |
| Delete router interface | Remove VPC from IG |
| Delete router | Remove IG |

#### Notes

**Networks**

1. Only supports tenant network creation. Tenant network subnet should be a CIDR smaller than /16. **create network** assumes /16 CIDR based on the first subnet that will be created in that network/vpc. This is needed as VPC in AWS needs a CIDR.
    - Example - 1 network (Paul) with 0 subnets in Openstack. AWS will have 0 VPCs and 0 subnets. Upon creating a subnet (Blart) under the Paul network with a CIDR of 12.12.1.5/26, the VPC on AWS will be created with CIDR 12.12.1.5/16, then a subnet under that VPC will be created with the actual CIDR (which is a subset of the VPC CIDR). The reason /16 is chosen for the CIDR of the VPC is because this is the largest mask allowed by AWS.
2. Subsequent subnets can be created within the same network (VPC)
3. When creating a subnet, set the allocation pool to x.x.x.4 - x.x.x.254 This is needed as AWS has reserved IPs from .0 till .3. http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html
4. For Floating IPs to work, an External Network with subnet like CIDR 52.0.0.0/8 which covers all the IPs that AWS provides needs to be created. If AWS assigns an elastic IP from within 54.0.0.0/8, the external subnet should reflect that.

###### Limitations

1. Provider networks not supported today.
2. External network subnet needs to be created manually depending on elastic IPs given by AWS.
3. IPv6 not supported by AWS VPC (https://aws.amazon.com/vpc/faqs/).

**Routers**

1. Creating a Router will create an Internet Gateway on AWS without associating to any VPC.
2. Add an Interface to Router connecting to any subnet will associate the VPC to that IG and also adds a default route of 0.0.0.0/0 to the IG.

###### Limitations

1. Adding an Interface with a subnet of another network will not work as an IG can be associated with a single VPC.
2. Adding an Interface with a subnet of same network will not work because Internet Gateway gets associated with VPC and not Subnets.

**Security Groups**

Secruity groups will be implemented in the future. Currently for a tenant network created (Amazon VPC), the user will need to log into the AWS portal and assign the secruity group for the VPC. This needs to be done to allow an instance on the network  to talk to the outside world.

