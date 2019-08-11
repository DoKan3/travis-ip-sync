import boto3
import dns.resolver

SECURITY_GROUPS = {
    "production": [],
    "staging": [],
    "development": [],
}


def changeGroups(session, travis_addr, env):
    for securityGroupId in SECURITY_GROUPS[env]:
        security_group_addr = getSecGroupIps(session, securityGroupId)
        ec2 = session.resource("ec2")
        sg = ec2.SecurityGroup(securityGroupId)
        new_ips = set(travis_addr) - set(security_group_addr)

        if new_ips:
            for cidr in security_group_addr:
                sg.revoke_ingress(IpPermissions = [{'IpProtocol': '-1', 'IpRanges': [{'CidrIp': cidr}]}])
            for addr in travis_addr:
                sg.authorize_ingress(
                    IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": addr}]}]
                )
        print("done " + env)


def assumeRole(role_arn, session_name):
    sts = boto3.client("sts")
    response = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    credentials = response["Credentials"]
    return credentials


def getTravisIps():
    answer = sorted(dns.resolver.query("nat.travisci.net", "A"))
    return [i.address + "/32" for i in answer]


def getSecGroupIps(session, sg):
    ec2 = session.client("ec2")
    response = ec2.describe_security_groups(GroupIds=[sg])
    cidrs = sorted(cidrs_from_response(response))
    return cidrs


def cidrs_from_response(response):
    cidrs_dict = []
    sg = response["SecurityGroups"]
    for data in sg:
        permissions = data["IpPermissions"]
        for p in permissions:
            ip_ranges = p["IpRanges"]
            for ip in ip_ranges:
                cidrs_dict.append(ip["CidrIp"])
    return cidrs_dict


def buildSession(credentials):
    session = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
        region_name="us-east-1",
    )
    return session


def main():
    travis_addr = getTravisIps()
    for env in SECURITY_GROUPS:
        if env == "production":
            role_arn = ""
            session_name = "travis-sync-prod"
        elif env == "staging":
            role_arn = ""
            session_name = "travis-sync-staging"
        elif env == "development":
            role_arn = ""
            session_name = "travis-sync-dev"

        print("Starting " + env)
        credentials = assumeRole(role_arn, session_name)
        session = buildSession(credentials)
        changeGroups(session, travis_addr, env)


if __name__ == "__main__":
    main()
