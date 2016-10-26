## Setup

### Prerequesites
1. Working green field OpenStack deployment.
2. No prior cinder nodes. This service does not work if cinder backends are already configured.
3. The virtualenv used by cinder should have Amazon boto package installed


### Instructions
1. Copy source directory (cinder/volume/drivers/aws) to cinder-volume module directory {cinder-volume-root}/cinder/volume/drivers
2. Update configuration file (cinder.conf) used by cinder-volume service. Set it to
   volume_driver=cinder.volume.drivers.aws.ebs.EBSDriver
3. Restart cinder-volume service.
