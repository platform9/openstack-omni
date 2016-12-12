
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