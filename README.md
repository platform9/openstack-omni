** Update **
Openstack-Omni is now an Openstack Big Tent project. This repository is now depreciated in favor of https://github.com/openstack/omni. Please use the main Openstack repo for future work related to Omni.

OpenStack-Omni aims to provide a standard OpenStack API for managing hybrid and multi-cloud environments.
This repository contains Openstack drivers for various public cloud environments.
These drivers currently provide the capability to spin up Openstack instances, images, volumes and networks on Amazon EC2. We need contributions to support other public cloud environments like Azure, Google Compute Engine, Rackspace, etc.
Following Openstack projects are supported --
* Nova
* Neutron
* Cinder
* Glance

Check out this video at Openstack Barcelona 2016 Keynote to find out more:
[![Omni Demo @Keynote](http://i.imgur.com/IDqYoQ3.jpg)](https://www.youtube.com/watch?v=U_LA7ZwQ9og)

## Setup
The setup instructions are project specific. Check the project directories for specifics.

## Status
Development is active. Can be used for individual testing.

## Contributions
Contributions are welcome. Specifically following areas need help:

1. Similar drivers for Windows Azure, Google Compute Engine and other public cloud providers
2. Following blueprints track the integration with OpenStack:
   * Nova: https://blueprints.launchpad.net/nova/+spec/nova-aws
   * Neutron: https://bugs.launchpad.net/neutron/+bug/1638399
   * Glance: https://blueprints.launchpad.net/glance/+spec/glance-aws
   * Cinder: https://blueprints.launchpad.net/cinder/+spec/cinder-aws
   
   Help is needed in promoting these blueprints for next (O) release.
