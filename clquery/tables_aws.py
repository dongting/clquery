import boto3
from botocore.exceptions import ClientError

from .schema import BaseSchema, Field
from .clconfig import ClqueryConfig

class Aws(object):
    service_lookup = {}
    default_region = boto3.Session(
        profile_name=ClqueryConfig.get('aws_profile')
    ).region_name

    @classmethod
    def get_default_region(cls):
        return cls.default_region

    @classmethod
    def add_filter(cls, kwargs, filter_name, values):
        if values is not None:
            if 'Filters' not in kwargs:
                kwargs['Filters'] = []
            if type(values) != list:
                values = [values]
            kwargs['Filters'].append({'Name': filter_name, 'Values': values})

    @classmethod
    def apply(cls, service, api, regions=None, **kwargs):
        if type(regions) == str:
            regions = [regions]
        # 'region' should not have been set, should be 'regions'
        if 'region' in kwargs:
            regions = [kwargs['region']] \
                if kwargs['region'] is not None else None
            del kwargs['region']
        if regions is None:
            regions = cls._get_applicable_regions()

        result = []
        for region in regions:
            if 'NextToken' in kwargs:
                del kwargs['NextToken']
            resp = cls._apply_one_region(service, api, region, **kwargs)
            while resp:
                result.append((region, resp))
                if 'NextToken' in resp and resp['NextToken'] != '':
                    kwargs['NextToken'] = resp['NextToken']
                    resp = cls._apply_one_region(
                        service, api, region, **kwargs
                    )
                else:
                    break
        return result

    @classmethod
    def _get_client_for(cls, service, region):
        if region is None:
            region = cls.get_default_region()
        if service in cls.service_lookup and \
                region in cls.service_lookup[service]:
            session, client = cls.service_lookup[service][region]
        else:
            session = boto3.Session(
                profile_name=ClqueryConfig.get('aws_profile')
            )
            client = session.client(service, region_name=region)
            if service not in cls.service_lookup:
                cls.service_lookup[service] = {}
            cls.service_lookup[service][region] = (session, client)
        return client

    @classmethod
    def _get_applicable_regions(cls, **kwargs):
        regions = []
        kwargs = {
            'Filters': [{
                'Name': 'opt-in-status',
                'Values': ['opt-in-not-required', 'opted-in']
            }]
        }
        resp = cls._apply_one_region(
            'ec2', 'describe_regions',
            cls.get_default_region(),
            **kwargs
        )
        for region in resp['Regions']:
            if region['OptInStatus'] == 'opt-in-not-required' or \
                    region['OptInStatus'] == 'opted-in':
                regions.append(region['RegionName'])
        return regions

    @classmethod
    def _apply_one_region(cls, service, api, region, **kwargs):
        c = cls._get_client_for(service, region)
        return getattr(c, api)(**kwargs)


class AwsS3Bucket(BaseSchema):
    ''' APIs:
        - aws.s3.list_buckets
        - aws.s3.get_bucket_location
        - aws.s3.get_bucket_encryption
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_s3_bucket'
        self.register_fields([
            Field('region', 'TEXT'),
            Field('name', 'TEXT'),
            Field('creation_datetime', 'TEXT'),
            Field('creation_year', 'INTEGER'),
            Field('creation_month', 'INTEGER'),
            Field('creation_day', 'INTEGER'),
            Field('creation_hour', 'INTEGER'),
            Field('creation_minute', 'INTEGER'),
            Field('creation_second', 'INTEGER'),
            Field('owner_name', 'TEXT'),
            Field('owner_id', 'TEXT'),
            Field('default_encryption', 'TEXT')
        ])

    def get_data(self, constraints={}):
        data = []

        # S3 is global so only the default region is sufficient
        default_region = Aws.get_default_region()
        _, list_resp = Aws.apply(
            's3', 'list_buckets', regions=default_region
        )[0]
        owner_name = list_resp['Owner']['DisplayName']
        owner_id = list_resp['Owner']['ID']
        for bucket in list_resp['Buckets']:
            bucket_name = bucket['Name']
            dt = bucket['CreationDate']
            region = Aws.apply(
                's3', 'get_bucket_location',
                regions=default_region,
                Bucket=bucket_name
            )[0][1]['LocationConstraint']
            try:
                _, encr_resp = Aws.apply(
                    's3', 'get_bucket_encryption',
                    regions=default_region,
                    Bucket=bucket_name
                )[0]
            except ClientError as e:
                if e.response['Error']['Code'] == \
                        'ServerSideEncryptionConfigurationNotFoundError':
                    encr_resp = None
                else:
                    print('ClientError: {}'.format(e))
            if encr_resp and self.get_nested(
                encr_resp, ['ServerSideEncryptionConfiguration', 'Rules']
            ):
                encr = ','.join(list(map(
                    lambda x:
                    x['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'],
                    encr_resp['ServerSideEncryptionConfiguration']['Rules']
                )))
            else:
                encr = None
            # AWS returns None when bucket's region is us-east-1
            if region is None:
                region = 'us-east-1'
            data.append([
                region,
                bucket_name,
                dt.isoformat(), dt.year, dt.month, dt.day,
                dt.hour, dt.minute, dt.second,
                owner_name,
                owner_id,
                encr
            ])
        return data


class AwsEc2Region(BaseSchema):
    ''' APIs:
        - aws.ec2.describe_regions
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_ec2_region'
        self.register_fields([
            Field('region', 'TEXT', filterable=True),
            Field('endpoint', 'TEXT'),
            Field('opt_in_status', 'TEXT')
        ])

    def get_data(self, constraints={}):
        data = []
        kw = {'AllRegions': True}
        Aws.add_filter(kw, 'region-name', constraints.get('region'))
        default_region = Aws.get_default_region()
        _, resp = Aws.apply(
            'ec2', 'describe_regions',
            regions=default_region,
            **kw
        )[0]
        for region in resp['Regions']:
            data.append([
                region.get('RegionName'),
                region.get('Endpoint'),
                region.get('OptInStatus')
            ])
        return data


class AwsEc2KeyPair(BaseSchema):
    ''' APIs:
        - aws.ec2.describe_key_pairs
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_ec2_key_pair'
        self.register_fields([
            Field('region', 'TEXT', filterable=True),
            Field('name', 'TEXT'),
            Field('key_pair_id', 'TEXT'),
            Field('key_fingerprint', 'TEXT'),
        ])

    def get_data(self, constraints={}):
        data = []
        resps = Aws.apply(
            'ec2',
            'describe_key_pairs',
            regions=constraints.get('region', None)
        )
        for region, resp in resps:
            for keypair in resp['KeyPairs']:
                data.append([
                    region,
                    keypair.get('KeyName'),
                    keypair.get('KeyPairId'),
                    keypair.get('KeyFingerprint'),
                ])
        return data


class AwsEc2Instance(BaseSchema):
    ''' APIs:
        - aws.ec2.describe_instances
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_ec2_instance'
        self.register_fields([
            Field('region', 'TEXT', filterable=True),
            Field('instance_id', 'TEXT', filterable=True),
            Field('instance_state_name', 'TEXT', filterable=True),
            Field('instance_state_code', 'INTEGER', filterable=True),
            Field('instance_type', 'TEXT', filterable=True),
            Field('image_id', 'TEXT', filterable=True),
            Field('kernel_id', 'TEXT'),
            Field('key_name', 'TEXT'),
            Field('launch_datetime', 'TEXT'),
            Field('launch_year', 'INTEGER'),
            Field('launch_month', 'INTEGER'),
            Field('launch_day', 'INTEGER'),
            Field('launch_hour', 'INTEGER'),
            Field('launch_minute', 'INTEGER'),
            Field('launch_second', 'INTEGER'),
            Field('platform', 'TEXT', filterable=True),
            Field('iam_instance_profile_arn', 'TEXT', filterable=True),
            Field('iam_instance_profile_id', 'TEXT'),
            Field('owner_id', 'TEXT'),
        ])

    def get_data(self, constraints={}):
        data = []
        kw = {}
        Aws.add_filter(kw, 'instance-id', constraints.get('instance_id'))
        Aws.add_filter(kw, 'instance-type', constraints.get('instance_type'))
        Aws.add_filter(kw, 'image-id', constraints.get('image_id'))
        Aws.add_filter(kw, 'platform', constraints.get('platform'))
        Aws.add_filter(kw, 'iam-instance-profile.arn',
                       constraints.get('iam_instance_profile_arn'))

        resps = Aws.apply(
            'ec2',
            'describe_instances',
            regions=constraints.get('region'),
            **kw
        )
        for region, resp in resps:
            for res in resp['Reservations']:
                owner_id = res['OwnerId']
                for instance in res.get('Instances', []):
                    dt = instance['LaunchTime']
                    data.append([
                        region,
                        instance.get('InstanceId'),
                        instance.get('State').get('Name'),
                        instance.get('State').get('Code'),
                        instance.get('InstanceType'),
                        instance.get('ImageId'),
                        instance.get('KernelId'),
                        instance.get('KeyName'),
                        dt.isoformat(), dt.year, dt.month, dt.day,
                        dt.hour, dt.minute, dt.second,
                        instance.get('Platform'),
                        self.get_nested(
                            instance, ['IamInstanceProfile', 'Arn']),
                        self.get_nested(
                            instance, ['IamInstanceProfile', 'Id']),
                        owner_id
                    ])
        return data


class AwsEc2NetworkInterface(BaseSchema):
    ''' APIs
        - aws.ec2.describe_network_interfaces

        Note that each network interface may contain multiple sets of
        private DNS/addresses, and each may associate with zero or one
        public DNS/addresses. Here we list each private DNS/addresses
        as a separate row, which means for a network interface with
        2 private IPs, the same network interface id will show up 2
        times.
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_ec2_network_interface'
        self.register_fields([
            Field('region', 'TEXT', filterable=True),
            Field('interface_id', 'TEXT', filterable=True),
            Field('interface_type', 'TEXT'),
            Field('attached_instance_id', 'TEXT', filterable=True),
            Field('subnet_id', 'TEXT', filterable=True),
            Field('vpc_id', 'TEXT', filterable=True),
            Field('private_dns', 'TEXT'),
            Field('private_ip', 'TEXT',),
            Field('public_dns', 'TEXT'),
            Field('public_ip', 'TEXT'),
            Field('is_primary', 'TEXT', filterable=True),
            Field('mac_address', 'TEXT', filterable=True),
            Field('src_dst_check', 'TEXT'),
        ])

    def get_data(self, constraints={}):
        data = []
        kw = {}
        Aws.add_filter(kw, 'network-interface-id', constraints.get('interface_id'))
        Aws.add_filter(kw, 'attachment.instance-id',
                       constraints.get('attached_instance_id'))
        Aws.add_filter(kw, 'subnet-id', constraints.get('subnet_id'))
        Aws.add_filter(kw, 'vpc-id', constraints.get('vpc_id'))
        Aws.add_filter(kw, 'addresses.primary', constraints.get('is_primary'))
        Aws.add_filter(kw, 'mac-address', constraints.get('mac_address'))

        resps = Aws.apply(
            'ec2',
            'describe_network_interfaces',
            regions=constraints.get('region'),
            **kw
        )
        for region, resp in resps:
            for interface in resp['NetworkInterfaces']:
                row = [
                    region,
                    interface.get('NetworkInterfaceId'),
                    interface.get('InterfaceType'),
                    self.get_nested(interface, ['Attachment', 'InstanceId']),
                    interface.get('SubnetId'),
                    interface.get('VpcId'),
                    interface.get('PrivateDnsName'),
                    interface.get('PrivateIpAddress'),
                    self.get_nested(
                        interface, ['Association', 'PublicDnsName']
                    ),
                    self.get_nested(interface, ['Association', 'PublicIp']),
                    True,
                    interface.get('MacAddress'),
                    interface.get('SourceDestCheck')
                ]
                data.append(row)
                for private_ip in interface['PrivateIpAddresses']:
                    row = [
                        region,
                        interface.get('NetworkInterfaceId'),
                        interface.get('InterfaceType'),
                        self.get_nested(
                            interface, ['Attachment', 'InstanceId']),
                        interface.get('SubnetId'),
                        interface.get('VpcId'),
                        private_ip.get('PrivateDnsName'),
                        private_ip.get('PrivateIpAddress'),
                        self.get_nested(
                            private_ip, ['Association', 'PublicDnsName']
                        ),
                        self.get_nested(
                            private_ip, ['Association', 'PublicIp']
                        ),
                        private_ip.get('Primary'),
                        interface.get('MacAddress'),
                        interface.get('SourceDestCheck')
                    ]
                    data.append(row)
        return self.dedupe(data)


class AwsEc2InstanceSecurityGroup(BaseSchema):
    ''' APIs:
        - aws.ec2.describe_instances

        This table is a many-to-many join table of instance IDs and
        security group IDs
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_ec2_instance_security_group'
        self.register_fields([
            Field('region', 'TEXT', filterable=True),
            Field('instance_id', 'TEXT', filterable=True),
            Field('security_group_id', 'TEXT', filterable=True),
            Field('security_group_name', 'TEXT', filterable=True),
        ])

    def get_data(self, constraints={}):
        data = []
        kw = {}
        Aws.add_filter(kw, 'instance-id', constraints.get('instance_id'))
        Aws.add_filter(
            kw, 'instance.group-id', constraints.get('security_group_id')
        )
        Aws.add_filter(
            kw, 'instance.group-name', constraints.get('security_group_name')
        )

        resps = Aws.apply(
            'ec2',
            'describe_instances',
            regions=constraints.get('region'),
            **kw
        )
        for region, resp in resps:
            for res in resp['Reservations']:
                for instance in res.get('Instances', []):
                    for sg in instance.get('SecurityGroups', []):
                        data.append([
                            region,
                            instance.get('InstanceId'),
                            sg.get('GroupId'),
                            sg.get('GroupName'),
                        ])
        return data


class AwsEc2SecurityGroupRule(BaseSchema):
    ''' APIs:
        - aws.ec2.describe_security_groups

        This table shows one rule per row, i.e. each Security
        Group ID may show up multiple times.

        The `target` of a rule, which is the source in the case of ingress
        and destination in the case of egress, can be one of three:
        1. IP CIDR (column ip_range), for when it's an IP
        2. Prefix list ID (column prefix_list_id), for AWS internal
           endpoints
        3. A referenced security group, either owned by the same owner
           or by another owner (cross-account) over a VPC peering link.
           Cross-region with any owner does not seem to be supported
           right now. (columns ref_*))
        In one row, exactly one of the above 3 column(s) would have data,
        the other two would be NULL.
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_ec2_security_group_rule'
        self.register_fields([
            Field('region', 'TEXT', filterable=True),
            Field('vpc_id', 'TEXT', filterable=True),
            Field('security_group_id', 'TEXT', filterable=True),
            Field('security_group_name', 'TEXT', filterable=True),
            Field('direction', 'TEXT'),  # 'ingress' or 'egress'
            Field('ip_protocol', 'TEXT'),
            Field('ip_range', 'TEXT'),
            Field('prefix_list_id', 'TEXT'),
            Field('ref_security_group_id', 'TEXT'),
            Field('ref_vpc_peering_connection_id', 'TEXT'),
            Field('from_port', 'TEXT'),
            Field('to_port', 'TEXT'),
        ])

    def get_data(self, constraints={}):
        data = []
        kw = {}
        Aws.add_filter(kw, 'vpc-id', constraints.get('vpc_id'))
        Aws.add_filter(kw, 'group-id', constraints.get('security_group_id'))
        Aws.add_filter(kw, 'group-name',
                       constraints.get('security_group_name'))

        resps = Aws.apply(
            'ec2',
            'describe_security_groups',
            regions=constraints.get('region'),
            **kw
        )
        for region, resp in resps:
            for sg in resp['SecurityGroups']:
                for perm, direction in zip(
                    sg['IpPermissions'] + sg['IpPermissionsEgress'],
                    ['ingress', 'egress']
                ):
                    for cidr in perm.get('IpRanges', []):
                        data.append([
                            region,
                            sg.get('VpcId'),
                            sg.get('GroupId'),
                            sg.get('GroupName'),
                            direction,
                            perm.get('IpProtocol'),
                            cidr.get('CidrIp'),
                            None,
                            None,
                            None,
                            perm.get('FromPort'),
                            perm.get('ToPort')
                        ])
                    for pl in perm.get('PrefixListIds', []):
                        data.append([
                            region,
                            sg.get('VpcId'),
                            sg.get('GroupId'),
                            sg.get('GroupName'),
                            direction,
                            perm.get('IpProtocol'),
                            None,
                            pl.get('PrefixListId'),
                            None,
                            None,
                            perm.get('FromPort'),
                            perm.get('ToPort')
                        ])
                    for uig in perm.get('UserIdGroupPairs', []):
                        data.append([
                            region,
                            sg.get('VpcId'),
                            sg.get('GroupId'),
                            sg.get('GroupName'),
                            direction,
                            perm.get('IpProtocol'),
                            None,
                            None,
                            uig.get('GroupId'),
                            uig.get('VpcPeeringConnectionId'),
                            perm.get('FromPort'),
                            perm.get('ToPort')
                        ])
        return data


class AwsVpc(BaseSchema):
    ''' APIs:
        - aws.ec2.describe_vpcs

        If a VPC has multiple CIDRs associated with it, it will get
        multiple rows with one row per VPC + CIDR.

        Note that even though the AWS endpoint falls under ec2 client,
        I am promoting VPCs to a first class citizen in line with
        AWS console.
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_vpc'
        self.register_fields([
            Field('region', 'TEXT', filterable=True),
            Field('vpc_id', 'TEXT', filterable=True),
            Field('cidr', 'TEXT'),
            Field('dhcp_options_id', 'TEXT'),
            Field('is_default', 'TEXT')
        ])

    def get_data(self, constraints={}):
        data = []
        kw = {}
        Aws.add_filter(kw, 'vpc-id', constraints.get('vpc_id'))

        resps = Aws.apply(
            'ec2',
            'describe_vpcs',
            regions=constraints.get('region'),
            **kw
        )
        for region, resp in resps:
            for vpc in resp['Vpcs']:
                data.append([
                    region,
                    vpc.get('VpcId'),
                    vpc.get('CidrBlock'),
                    vpc.get('DhcpOptionsId'),
                    vpc.get('IsDefault')
                ])
                for assn in vpc.get('CidrBlockAssociationSet', []):
                    data.append([
                        region,
                        vpc.get('VpcId'),
                        assn.get('CidrBlock'),
                        vpc.get('DhcpOptionsId'),
                        vpc.get('IsDefault')
                    ])
        return self.dedupe(data)


class AwsVpcPeeringConnection(BaseSchema):
    ''' APIs:
        - aws.ec2.describe_vpc_peering_connections
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_vpc_peering_connection'
        self.register_fields([
            Field('vpc_peering_connection_id', 'TEXT', filterable=True),
            Field('requester_owner_id', 'TEXT', filterable=True),
            Field('requester_region', 'TEXT'),
            Field('requester_vpc_id', 'TEXT', filterable=True),
            Field('requester_vpc_cidr', 'TEXT'),
            Field('accepter_owner_id', 'TEXT', filterable=True),
            Field('accepter_region', 'TEXT'),
            Field('accepter_vpc_id', 'TEXT', filterable=True),
            Field('accepter_vpc_cidr', 'TEXT'),
            Field('status', 'TEXT'),
        ])

    def get_data(self, constraints={}):
        data = []
        kw = {}
        Aws.add_filter(kw, 'vpc-peering-connection-id',
                       constraints.get('vpc_peering_connection_id'))
        Aws.add_filter(kw, 'requester-vpc-info.owner-id',
                       constraints.get('requester_owner_id'))
        Aws.add_filter(kw, 'requester-vpc-info.vpc-id',
                       constraints.get('requester_vpc_id'))
        # Aws.add_filter(kw, 'requester-vpc-info.cidr-block',
                       # constraints.get('requester_vpc_cidr'))
        Aws.add_filter(kw, 'accepter-vpc-info.owner-id',
                       constraints.get('accepter_owner_id'))
        Aws.add_filter(kw, 'accepter-vpc-info.vpc-id',
                       constraints.get('accepter_vpc_id'))
        # Aws.add_filter(kw, 'accepter-vpc-info.cidr-block',
                       # constraints.get('accepter_vpc_cidr'))

        resps = Aws.apply(
            'ec2',
            'describe_vpc_peering_connections',
            regions=None,
            **kw
        )
        for region, resp in resps:
            for px in resp['VpcPeeringConnections']:
                req_cidrs = [px['RequesterVpcInfo'].get('CidrBlock')] + \
                            [x['CidrBlock'] for x in
                             px['RequesterVpcInfo'].get('CidrBlockSet', [])]
                acc_cidrs = [px['AccepterVpcInfo'].get('CidrBlock')] + \
                            [x['CidrBlock'] for x in
                             px['AccepterVpcInfo'].get('CidrBlockSet', [])]
                for req_cidr in req_cidrs:
                    for acc_cidr in acc_cidrs:
                        if req_cidr is None or acc_cidr is None:
                            continue
                        data.append([
                            px.get('VpcPeeringConnectionId'),
                            self.get_nested(
                                px, ['RequesterVpcInfo', 'OwnerId']),
                            self.get_nested(
                                px, ['RequesterVpcInfo', 'Region']),
                            self.get_nested(
                                px, ['RequesterVpcInfo', 'VpcId']),
                            req_cidr,
                            self.get_nested(
                                px, ['AccepterVpcInfo', 'OwnerId']),
                            self.get_nested(
                                px, ['AccepterVpcInfo', 'Region']),
                            self.get_nested(
                                px, ['AccepterVpcInfo', 'VpcId']),
                            acc_cidr,
                            self.get_nested(px, ['Status', 'Code'])
                        ])
        return self.dedupe(data)


class AwsVpcSubnet(BaseSchema):
    ''' APIs:
        - aws.ec2.describe_subnets
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_subnet'
        self.register_fields([
            Field('region', 'TEXT', filterable=True),
            Field('subnet_id', 'TEXT', filterable=True),
            Field('vpc_id', 'TEXT', filterable=True),
            Field('cidr', 'TEXT', filterable=True),
            Field('default_for_az', 'TEXT'),
            Field('public_ip_on_launch', 'TEXT'),
            Field('available_ip_address_count', 'INTEGER'),
            Field('availability_zone', 'TEXT'),
            Field('availability_zone_id', 'TEXT')
        ])

    def get_data(self, constraints={}):
        data = []
        kw = {}
        Aws.add_filter(kw, 'subnet-id', constraints.get('subnet_id'))
        Aws.add_filter(kw, 'vpc-id', constraints.get('vpc_id'))
        Aws.add_filter(kw, 'cidr-block', constraints.get('cidr'))

        resps = Aws.apply(
            'ec2',
            'describe_subnets',
            regions=constraints.get('region'),
            **kw
        )
        for region, resp in resps:
            for subnet in resp['Subnets']:
                data.append([
                    region,
                    subnet.get('SubnetId'),
                    subnet.get('VpcId'),
                    subnet.get('CidrBlock'),
                    subnet.get('DefaultForAz'),
                    subnet.get('MapPublicIpOnLaunch'),
                    subnet.get('AvailableIpAddressCount'),
                    subnet.get('AvailabilityZone'),
                    subnet.get('AvailabilityZoneId')
                ])
        return data


# class AwsVpcRouteTable(BaseSchema):
#     ''' APIs:
#         - aws.ec2.describe_route_tables
#     '''
#     pass


class AwsElasticIp(BaseSchema):
    ''' APIs:
        - aws.ec2.describe_addresses
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_elastic_ip'
        self.register_fields([
            Field('region', 'TEXT', filterable=True),
            Field('public_ip', 'TEXT', filterable=True),
            Field('private_ip', 'TEXT', filterable=True),
            Field('instance_id', 'TEXT', filterable=True),
            Field('network_interface_id', 'TEXT', filterable=True),
            Field('network_interface_owner_id', 'TEXT'),
            Field('allocation_id', 'TEXT'),
            Field('association_id', 'TEXT'),
            Field('domain', 'TEXT')
        ])

    def get_data(self, constraints={}):
        data = []
        kw = {}
        Aws.add_filter(kw, 'public-ip', constraints.get('public_ip'))
        Aws.add_filter(kw, 'private-ip-address', constraints.get('private_ip'))
        Aws.add_filter(kw, 'instance-id', constraints.get('instance_id'))
        Aws.add_filter(kw, 'network-interface-id',
                       constraints.get('network_interface_id'))

        resps = Aws.apply(
            'ec2',
            'describe_addresses',
            regions=constraints.get('region'),
            **kw
        )
        for region, resp in resps:
            for addr in resp['Addresses']:
                data.append([
                    region,
                    addr.get('PublicIp'),
                    addr.get('PrivateIpAddress'),
                    addr.get('InstanceId'),
                    addr.get('NetworkInterfaceId'),
                    addr.get('NetworkInterfaceOwnerId'),
                    addr.get('AllocationId'),
                    addr.get('AssociationId'),
                    addr.get('Domain')
                ])
        return data


class AwsImage(BaseSchema):
    ''' APIs:
        - aws.ec2.describe_images

        Note this will only include images that you have explicit launch
        permissions, and not general public ones since there are too many.
        (ExecutableUsers='self')
    '''

    def __init__(self):
        super().__init__()
        self.table_name = 'aws_image'
        self.register_fields([
            Field('region', 'TEXT', filterable=True),
            Field('image_id', 'TEXT', filterable=True),
            Field('image_name', 'TEXT'),
            Field('image_location', 'TEXT'),
            Field('image_type', 'TEXT'),
            Field('architecture', 'TEXT'),
            Field('creation_datetime', 'TEXT'),
            Field('creation_year', 'INTEGER'),
            Field('creation_month', 'INTEGER'),
            Field('creation_day', 'INTEGER'),
            Field('creation_hour', 'INTEGER'),
            Field('creation_minute', 'INTEGER'),
            Field('creation_second', 'INTEGER'),
            Field('is_public', 'TEXT'),
            Field('kernel_id', 'TEXT'),
            Field('owner_id', 'TEXT'),
            Field('state', 'TEXT'),
            Field('root_device_name', 'TEXT'),
            Field('root_device_type', 'TEXT'),
            Field('virtualization_type', 'TEXT')
        ])

    def get_data(self, constraints={}):
        data = []
        kw = {}
        Aws.add_filter(kw, 'image-id', constraints.get('image_id'))
        kw['ExecutableUsers'] = ['self']

        resps = Aws.apply(
            'ec2',
            'describe_images',
            regions=constraints.get('region'),
            **kw
        )
        for region, resp in resps:
            for image in resp['Images']:
                dt = image['CreationDate']
                data.append([
                    region,
                    image.get('ImageId'),
                    image.get('Name'),
                    image.get('ImageLocation'),
                    image.get('ImageType'),
                    image.get('Architecture'),
                    dt.isoformat(), dt.year, dt.month, dt.day,
                    dt.hour, dt.minute, dt.second,
                    image.get('Public'),
                    image.get('KernelId'),
                    image.get('OwnerId'),
                    image.get('State'),
                    image.get('RootDeviceName'),
                    image.get('RootDeviceType'),
                    image.get('VirtualizationType')
                ])
        return data


#
# lambda?