#!/usr/bin/env python3

# The purpose of this script is to create a Config Aggregator
# in an Organizations Member Account that Aggregates all of your
# Organization's Member Accounts across all supported Regions.
# Note: you must run this in an Organizations Master Account

import json, os, boto3

def lambda_handler(event, context):
    # Each Member Account must have an OrganizationAccountAccessRole
    # that matches the string provided to the variable ORGS_ACCESS_ROLE_NAME
    # the OrganizationAccountAccessRole must have the proper IAM permissions
    ORGS_ACCESS_ROLE_NAME = 'OrganizationAccountAccessRole'
    CONFIGURATION_AGGREGATOR_NAME = 'ConfigAggregator1'
    
    SEE_LOGS = ', please see the logs.'
    if 'AGGREGATOR_ACCOUNT' in os.environ:
        aggregator_account = os.environ['AGGREGATOR_ACCOUNT']
    else:
        ENV_NOT_SET = 'AGGREGATOR_ACCOUNT Environment Variable is not set.'
        ENV_NOT_SET += ' Please set this variable to a Member Account Number'
        print(ENV_NOT_SET + ', exiting...')
        return ENV_NOT_SET
    result = create_aggregator(ORGS_ACCESS_ROLE_NAME, CONFIGURATION_AGGREGATOR_NAME, aggregator_account)
    
    if result == 0:
        return 'Aggregator created sucessfully' + SEE_LOGS
    return 'Aggregator script abourted' + SEE_LOGS

def create_aggregator(ORGS_ACCESS_ROLE_NAME, CONFIGURATION_AGGREGATOR_NAME, aggregator_account):
    # disabled getting regions automatically for now as
    # get_available_regions() returns unsupported regions for Config Aggregator
    #config_regions=boto3.session.Session().get_available_regions('config')
    regions = 'ap-south-1 ap-northeast-2 ap-southeast-1 ap-southeast-2 ap-northeast-1 ca-central-1 \
    eu-central-1 eu-west-1 eu-west-2 eu-west-3 sa-east-1 us-east-1 us-east-2 us-west-1 us-west-2'
    config_regions = regions.split()
    
    continue_on_error = 'y'
    
    orgs = boto3.client('organizations')

    try:
        organization = orgs.describe_organization()['Organization']
    except Exception as e:
        print(e)
        return 1
    
    master_account_id = organization['MasterAccountId']
    
    try:
        account_ids = []
        paginator = orgs.get_paginator('list_accounts')
        for page in paginator.paginate():
            for account in page['Accounts']:
                account_ids.append(account['Id'])
        if aggregator_account not in account_ids:
            print('The Account Id that you entered is not within the Organization!')
            return 1 
        if aggregator_account == master_account_id:
            print('This script is meant to create a Config Aggregator in a Member Account')
            print('Please choose an Account that is not the Master Account')
            return 1 
    except Exception as e:
        print(e)
    
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
        return 1 
    
    config = boto3.client('config',
                          aws_access_key_id=member_credentials['AccessKeyId'],
                          aws_secret_access_key=member_credentials['SecretAccessKey'],
                          aws_session_token=member_credentials['SessionToken'],
                          )
    
    aggregation_accounts_with_errors = []
    
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
                member_config = boto3.client('config',
                                             aws_access_key_id=credentials['AccessKeyId'],
                                             aws_secret_access_key=credentials['SecretAccessKey'],
                                             aws_session_token=credentials['SessionToken'],
                                             )
                for region in config_regions:
                    print('Authorizing Region: ' + region)
                    member_config.put_aggregation_authorization(
                        AuthorizedAccountId=aggregator_account,
                        AuthorizedAwsRegion=region
                    )
                authorizations = member_config.describe_aggregation_authorizations()
                print('Sucessfully Authorized Regions in ' + account + ': ')
                for authorization in authorizations['AggregationAuthorizations']:
                    print(authorization['AuthorizedAwsRegion'])
            if account == master_account_id:
                master_config = boto3.client('config')
                for region in config_regions:
                    print('Authorizing Region: ' + region)
                    master_config.put_aggregation_authorization(
                        AuthorizedAccountId=aggregator_account,
                        AuthorizedAwsRegion=region
                    )
                authorizations = master_config.describe_aggregation_authorizations()
                print('Sucessfully Authorized Regions in ' + account + ': ')
                for authorization in authorizations['AggregationAuthorizations']:
                    print(authorization['AuthorizedAwsRegion'])
        except Exception as e:
            print(e)
            print('An error occoured in ' + account)
            aggregation_accounts_with_errors.append(account)
            while continue_on_error not in ['y', 'a']:
                if continue_on_error.lower().startswith('y'):
                    print("Continuing")
                    continue_on_error = 'unknown'
                    break
                elif continue_on_error.lower().startswith('a'):
                    print("Continuing")
                    continue_on_error = 'a'
                elif continue_on_error.lower().startswith('n'):
                    print("Exiting")
                    return 1 
    
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
        return 1 
    
    return 0
