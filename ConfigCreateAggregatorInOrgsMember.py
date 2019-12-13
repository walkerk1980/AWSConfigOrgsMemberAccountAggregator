#!/usr/bin/env python3

# The purpose of this script is to create a Config Aggregator
# in an Organizations Member Account that Aggregates all of your
# Organization's Member Accounts across all supported Regions.
# Note: you must run this in an Organizations Master Account

# Each Member Account must have an OrganizationAccountAccessRole
# that matches the string provided to the variable ORGS_ACCESS_ROLE_NAME
# the OrganizationAccountAccessRole must have the proper IAM permissions

import boto3
ORGS_ACCESS_ROLE_NAME = 'OrganizationAccountAccessRole'

CONFIGURATION_AGGREGATOR_NAME = 'ConfigAggregator1'
aggregator_region = None

# disabled getting regions automatically for now as
# get_available_regions() returns unsupported regions for Config Aggregator
#config_regions=boto3.session.Session().get_available_regions('config')
regions = 'ap-south-1 ap-northeast-2 ap-southeast-1 ap-southeast-2 ap-northeast-1 ca-central-1 \
eu-central-1 eu-west-1 eu-west-2 eu-west-3 sa-east-1 us-east-1 us-east-2 us-west-1 us-west-2'
config_regions = regions.split()

orgs = boto3.client('organizations')

try:
    organization = orgs.describe_organization()['Organization']
except Exception as e:
    print(e)
    exit(1)

master_account_id = organization['MasterAccountId']

aggregation_accounts_with_errors = []

continue_on_error = None
def keep_going(account):
        print('An error occoured in ' + account)
        global continue_on_error
        while continue_on_error not in ['y', 'a']:
            continue_on_error = input('Do you want to continue? Y/A/N: ')
            if continue_on_error.lower().startswith('y'):
                print("Continuing")
                continue_on_error = 'unknown'
                return
            elif continue_on_error.lower().startswith('a'):
                print("Continuing")
                continue_on_error = 'a'
            elif continue_on_error.lower().startswith('n'):
                print("Exiting")
                exit(1)

try:
    account_ids = []
    paginator = orgs.get_paginator('list_accounts')
    for page in paginator.paginate():
        for account in page['Accounts']:
            account_ids.append(account['Id'])
            print(account['Id'])
    aggregator_account = input(
        'Please choose the Account that you want the Aggregator to created in: ')
    aggregator_region = input(
        'Please choose the Region that you want the Aggregator to be created in: ')
    if aggregator_account not in account_ids:
        print('The Account Id that you entered is not within the Organization!')
        exit(1)
    if aggregator_account == master_account_id:
        print('This script is meant to create a Config Aggregator in a Member Account')
        print('Please choose an Account that is not the Master Account')
        exit(1)
except Exception as e:
    print(e)

def put_auth(config_client, aggregator_account, aggregator_region, config_region, authorization_account):
    try:
        config_client.put_aggregation_authorization(
            AuthorizedAccountId=aggregator_account,
            AuthorizedAwsRegion=aggregator_region
        )
        authorizations = config_client.describe_aggregation_authorizations()
        print('Sucessfully authorized Aggregator in ' + config_region + ' in ' + authorization_account + ': ')
        for authorization in authorizations.get('AggregationAuthorizations'):
            if authorization.get('AuthorizedAwsRegion') == config_region:
                print(authorization.get('AuthorizedAwsRegion'))
                print('Success!')
    except Exception as re:
        print('Error accpeting in ' + config_region)
        print(re)
        return(re)

def delete_auth(config_client, aggregator_account, aggregator_region, config_region, authorization_account):
    try:
        config_client.delete_aggregation_authorization(
            AuthorizedAccountId=aggregator_account,
            AuthorizedAwsRegion=aggregator_region
        )
        authorizations = config_client.describe_aggregation_authorizations()
        print('Sucessfully Deleted authorization in Region ' + config_region + ' in ' + authorization_account + ': ')
        for authorization in authorizations.get('AggregationAuthorizations'):
            print('Deleting authorizations in ' + account + ' ' + config_region)
    except Exception as re:
        print('Error deleting in ' + config_region)
        print(re)
        pass

sts = boto3.client('sts')

member_orgs_role_arn = 'arn:aws:iam::' + \
    aggregator_account + ':role/' + ORGS_ACCESS_ROLE_NAME

try:
    member_credentials = sts.assume_role(
        RoleArn=member_orgs_role_arn,
        RoleSessionName='ConfigAggregatorScript',
    )['Credentials']
except Exception as e:
    print(e)
    exit(1)

config = boto3.client('config',
                      aws_access_key_id=member_credentials['AccessKeyId'],
                      aws_secret_access_key=member_credentials['SecretAccessKey'],
                      aws_session_token=member_credentials['SessionToken'],
                      region_name=aggregator_region
                      )

for account in account_ids:
    print('Accepting Authorizations in Account: ' + account)
    account_orgs_role_arn = 'arn:aws:iam::' + \
        account + ':role/' + ORGS_ACCESS_ROLE_NAME
    try:
        if account not in [aggregator_account, master_account_id]:
            credentials = sts.assume_role(
                RoleArn=account_orgs_role_arn,
                RoleSessionName='ConfigAggregatorScript',
            )['Credentials']
            member_session = boto3.Session(aws_access_key_id=credentials['AccessKeyId'],
                                         aws_secret_access_key=credentials['SecretAccessKey'],
                                         aws_session_token=credentials['SessionToken'],
                )
            for config_region in config_regions:
                member_config = member_session.client('config', region_name=config_region)
                print('Authorizing Region: ' + config_region)
                e = put_auth(member_config, aggregator_account, aggregator_region, config_region, account)
                if e:
                    raise e
        if account == master_account_id:
            master_session = boto3.Session()
            for config_region in config_regions:
                master_config = master_session.client('config', region_name=config_region)
                print('Authorizing Region: ' + config_region)
                e = put_auth(master_config, aggregator_account, aggregator_region, config_region, account)
                if e:
                    raise e
    except Exception as e:
        print(e)
        keep_going(account)
        aggregation_accounts_with_errors.append(account)

try:
    config.put_configuration_aggregator(
        ConfigurationAggregatorName=CONFIGURATION_AGGREGATOR_NAME,
        AccountAggregationSources=[
            {
                'AllAwsRegions': True,
                'AccountIds': account_ids
            }
        ],
    )
    print('\n\rConfig Aggegator was created')
    print('Account: ' + aggregator_account)
    print('Aggregator: ' + CONFIGURATION_AGGREGATOR_NAME)
    if aggregation_accounts_with_errors:
        print('\n\rThere was an error putting Authorizations in the following Accounts: ')
        print(aggregation_accounts_with_errors)
        print('You may need to log in to these Accounts and manually authorize the Aggregator.')
except Exception as e:
    print(e)
    exit(1)
