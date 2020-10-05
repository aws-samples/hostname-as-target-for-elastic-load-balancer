import json
import logging
import os
import sys

import lambda_utils as utils

"""
Configure these environment variables in your Lambda environment or
CloudFormation Inputs settings):

1. TARGET_FQDN (mandatory): The Fully Qualified DNS Name used for application
cluster
2. ELB_TG_ARN (mandatory): The ARN of the Elastic Load Balancer's target group
3. S3_BUCKET (mandatory): Bucket to track changes between Lambda invocations
4. DNS_SERVER (mandatory): The DNS Servers to query TARGET_FQDN
5. BUCKET_REGION (optional): AWS Region for S3 Bucket
6. MAX_LOOKUP_PER_INVOCATION (optional): The max times of DNS look per
invocation
7. INVOCATIONS_BEFORE_DEREGISTRATION (optional): The number of required
Invocations before a IP is deregistered
8. REPORT_IP_COUNT_CW_METRIC (optional): Enable/Disable Hostname IP count
CloudWatch metric
9. REMOVE_UNKOWN_TG_IP (optional): Remove IPs that were not added by the
fucntion
"""
if 'TARGET_FQDN' in os.environ:
    TARGET_FQDN = os.environ['TARGET_FQDN']
else:
    print("ERROR: Missing Target Hostname.")
    sys.exit(1)

if 'ELB_TG_ARN' in os.environ:
    ELB_TG_ARN = os.environ['ELB_TG_ARN']
else:
    print("ERROR: Missing Destination Target Group ARN.")
    sys.exit(1)

if 'S3_BUCKET' in os.environ:
    S3_BUCKET = os.environ['S3_BUCKET']
else:
    print("ERROR: Missing S3 Bucket Name.")
    sys.exit(1)

if 'DNS_SERVER' in os.environ:
    DNS_SERVER = os.environ['DNS_SERVER']
else:
    print("ERROR: Missing Domain Name Server IP.")
    sys.exit(1)

if 'BUCKET_REGION' in os.environ:
    BUCKET_REGION = os.environ['BUCKET_REGION']
else:
    BUCKET_REGION = 'us-west-2'

if 'MAX_LOOKUP_PER_INVOCATION' in os.environ:
    MAX_LOOKUP_PER_INVOCATION = int(os.environ['MAX_LOOKUP_PER_INVOCATION'])
    if MAX_LOOKUP_PER_INVOCATION < 1:
        print("ERROR: Invalid MAX_LOOKUP_PER_INVOCATION value.")
        sys.exit(1)
else:
    MAX_LOOKUP_PER_INVOCATION = 10

if 'INVOCATIONS_BEFORE_DEREGISTRATION' in os.environ:
    INVOCATIONS_BEFORE_DEREGISTRATION = int(os.environ['INVOCATIONS_BEFORE_DEREGISTRATION'])
    if INVOCATIONS_BEFORE_DEREGISTRATION < 1:
        print("ERROR: Invalid INVOCATIONS_BEFORE_DEREGISTRATION value.")
        sys.exit(1)
else:
    INVOCATIONS_BEFORE_DEREGISTRATION = 3

if 'REPORT_IP_COUNT_CW_METRIC' in os.environ:
    REPORT_IP_COUNT_CW_METRIC = os.environ['REPORT_IP_COUNT_CW_METRIC'].capitalize()
    if isinstance(REPORT_IP_COUNT_CW_METRIC, str) and \
            REPORT_IP_COUNT_CW_METRIC == 'True':
        REPORT_IP_COUNT_CW_METRIC = True
    elif isinstance(REPORT_IP_COUNT_CW_METRIC, str) and \
            REPORT_IP_COUNT_CW_METRIC == 'False':
        REPORT_IP_COUNT_CW_METRIC = False
    elif isinstance(REPORT_IP_COUNT_CW_METRIC, bool):
        REPORT_IP_COUNT_CW_METRIC = REPORT_IP_COUNT_CW_METRIC
    else:
        print("ERROR: Invalid REPORT_IP_COUNT_CW_METRIC value. Expects "
              "boolean: True|False")
        sys.exit(1)
else:
    REPORT_IP_COUNT_CW_METRIC = True

if 'REMOVE_UNTRACKED_TG_IP' in os.environ:
    REMOVE_UNTRACKED_TG_IP = os.environ['REMOVE_UNTRACKED_TG_IP'].capitalize()
    if isinstance(REMOVE_UNTRACKED_TG_IP, str) and \
            REMOVE_UNTRACKED_TG_IP == 'True':
        REMOVE_UNTRACKED_TG_IP = True
    elif isinstance(REMOVE_UNTRACKED_TG_IP, str) and \
            REMOVE_UNTRACKED_TG_IP == 'False':
        REMOVE_UNTRACKED_TG_IP = False
    elif isinstance(REMOVE_UNTRACKED_TG_IP, bool):
        REMOVE_UNTRACKED_TG_IP = REMOVE_UNTRACKED_TG_IP
    else:
        print("ERROR: Invalid REPORT_IP_COUNT_CW_METRIC value. Expects "
              "boolean: True|False")
        sys.exit(1)
else:
    REMOVE_UNTRACKED_TG_IP = False


# MAIN Function - This function will be invoked when Lambda is called
def lambda_handler(event, context):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.info("INFO: Received event: {}".format(json.dumps(event)))
    # Get Currently Resgistered IPs list
    registered_ip_list = utils.describe_target_health(ELB_TG_ARN)

    # Create S3 Bucket / Verify Access to selected Bucket
    utils.create_s3_bucket(S3_BUCKET, BUCKET_REGION)

    # Query DNS for hostname IPs
    try:
        hostname_ip_list = []
        i = 1
        while i <= MAX_LOOKUP_PER_INVOCATION:
            dns_lookup_result = utils.dns_lookup(DNS_SERVER, TARGET_FQDN, "A")
            hostname_ip_list = dns_lookup_result + hostname_ip_list
            if len(dns_lookup_result) < 8:
                break
            i += 1
        logger.info(f"INFO: Hostname IPs resolved by DNS lookup: {hostname_ip_list}")

        # IPs that have not been registered, and missing from the old active IP list
        new_ips_to_register_list = list(set(hostname_ip_list) - set(registered_ip_list))

        # Register new targets
        if new_ips_to_register_list:
            utils.register_target(ELB_TG_ARN, new_ips_to_register_list)
            logger.info(f"INFO: Registering {format(new_ips_to_register_list)}")
        else:
            logger.info("INFO: No IPs to register.")

        # Set S3 object name
        s3_ip_list_key = ("Tracked IP list "
                          "for {} - {}".format(TARGET_FQDN, ELB_TG_ARN.replace('/', '-')))

        # Download previous IP Dictionary from S3
        ip_dict = utils.download_ip_list(S3_BUCKET, s3_ip_list_key)

        # Update IP Dictionary with current query results
        temp_hostname_ip_list = list(hostname_ip_list)
        expired_ip_list = []
        for ip in ip_dict:
            if ip not in (hostname_ip_list):
                ip_dict[ip] = ip_dict[ip] - 1
            else:
                temp_hostname_ip_list.remove(ip)
                ip_dict[ip] = INVOCATIONS_BEFORE_DEREGISTRATION
            if ip_dict[ip] == 0:
                expired_ip_list.append(ip)

        # Add new IPs to dictionary
        for ip in temp_hostname_ip_list:
            ip_dict[ip] = INVOCATIONS_BEFORE_DEREGISTRATION

        # If asked to track all IPs - Add all TG IPs to the tracking list
        if REMOVE_UNTRACKED_TG_IP:
            for ip in registered_ip_list:
                if ip not in ip_dict:
                    ip_dict[ip] = INVOCATIONS_BEFORE_DEREGISTRATION

        # Deregister IPs that were missing more than X times from the query
        for ip in expired_ip_list:
            if ip in expired_ip_list:
                ip_dict.pop(ip)

        if expired_ip_list:
            utils.deregister_target(ELB_TG_ARN, expired_ip_list)
        else:
            logger.info("INFO: No IPs to deregister.")

        # Update S3 IP Dictionary
        utils.upload_ip_list(S3_BUCKET, ip_dict, s3_ip_list_key)

        # Update CW metric
        if REPORT_IP_COUNT_CW_METRIC:
            utils.put_metric_data(ip_dict, TARGET_FQDN)

        # Report successful invocation
        logger.info("INFO: Update completed successfuly.")

    # Exception handler
    except Exception as e:
        logger.error("ERROR:", e)
        logger.error("ERROR: Invocation failed.")
        return(1)
    return (0)
