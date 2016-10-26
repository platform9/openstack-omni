# Copyright (c) 2016 Platform9 Systems Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


from nova import exception

class Ec2ExceptionHandler:
    """
        This is a class which can be used to create mapping between EC2 Exception messages to Nova based Exceptions.
        Also gives control on the error message displayed to the user.

    """
    @staticmethod
    def get_processed_exception(ec2_response_error_exc):
        if ec2_response_error_exc.error_code == "AuthFailure":
            return exception.Forbidden("Please check AWS credentials")
        elif ec2_response_error_exc.error_code == "InvalidAMIID.NotFound":
            return exception.ImageNotFoundEC2("Invalid Image")
        else:
            return exception.NovaException(ec2_response_error_exc.message)
