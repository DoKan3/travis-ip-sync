import boto3
from botocore.exceptions import ClientError
import dns.resolver

SECURITY_GROUPS = [''] #Add list of AWS security groups


def getTravisIps():
    answer = sorted(dns.resolver.query("nat.travisci.net", "A"))
    return [i.address + '/32' for i in answer]


def getSecGroupIps(sg):
    ec2 = boto3.client('ec2')
    response = ec2.describe_security_groups(GroupIds=[sg])
    cidrs = sorted(cidrs_from_response(response))
    return cidrs


def cidrs_from_response(response):
    cidrs_dict = []
    sg = response['SecurityGroups']
    for data in sg:
        permissions = data['IpPermissions']
        for p in permissions:
            ip_ranges = p['IpRanges']
            for ip in ip_ranges:
                cidrs_dict.append(ip['CidrIp'])
    return cidrs_dict


def main():
    travis_addr = getTravisIps()
    for securityGroupId in SECURITY_GROUPS:
        security_group_addr = getSecGroupIps(securityGroupId)
        ec2 = boto3.resource('ec2')
        sg = ec2.SecurityGroup(securityGroupId)
        new_ips = set(travis_addr) - set(security_group_addr)

        if new_ips:
            sg.revoke_ingress(IpPermissions=sg.ip_permissions)
            for addr in travis_addr:
                sg.authorize_ingress(IpPermissions=[{'IpProtocol': '-1',
                                                     'IpRanges':
                                                     [{'CidrIp': addr}]}])
        else:
            print('No new changes')


if __name__ == '__main__':
    main()
