import boto3
import grc_validation
from dotenv import load_dotenv
import os

def main():

    # Load environment variables
    load_dotenv()

    SN_I = os.getenv("SN_I")
    SN_T = os.getenv("SN_T")
    SN_U = os.getenv("SN_U")
    SN_P = os.getenv("SN_P")

    config_client = boto3.client('config')

    # Get Status of security controls
    statuses = grc_validation.get_all_control_statuses(config_client)

    # Update ServiceNow GRC table with statuses from AWS
    grc_validation.update_service_now(SN_I, SN_T, statuses, SN_U, SN_P)

if __name__ == "__main__":
    main()