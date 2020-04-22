from unittest import TestCase
from unittest.mock import patch
from datetime import datetime as dt
import boto3
from botocore.exceptions import ClientError

from clquery.tables_aws import *


default_region = 'us-west-2'
test_client = boto3.Session(
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='test'
).client('ec2')


@patch.object(Aws, '_get_client_for')
@patch.object(Aws, 'get_default_region')
@patch.object(Aws, 'apply')
class TestAws(TestCase):
    def test_pagination(self, mock_aws, mock_region, mock_client):
        pass

    def test_request_filter(self, mock_aws, mock_region, mock_client):
        pass

    def test_aws_s3_bucket(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp_list_buckets = [('us-west-2', {
            'Owner': {
                'DisplayName': 'test1',
                'ID': 123,
            },
            'Buckets': [
                {
                    'Name': 'test2',
                    'CreationDate': dt.fromisoformat('2020-01-02T03:04:05')
                },
                {
                    'Name': 'test3',
                    'CreationDate': dt.fromisoformat('2019-01-07T08:09:10')
                },
            ]
        })]
        resp_get_bucket_location_1 = [
            ('region-1', {'LocationConstraint': 'us-west-2'})
        ]
        resp_get_bucket_location_2 = [('region-2', {'LocationConstraint': None})]
        resp_get_bucket_encr_1 = [('region-3', {
            'ServerSideEncryptionConfiguration': {
                'Rules': [
                    {
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256',
                        }
                    },
                ]
            }
        })]
        response = {'Error': {
            'Code': 'ServerSideEncryptionConfigurationNotFoundError'
        }}
        resp_get_bucket_encr_2 = ClientError(
            response, '_'
        )
        mock_aws.side_effect = [
            resp_list_buckets,
            resp_get_bucket_location_1,
            resp_get_bucket_encr_1,
            resp_get_bucket_location_2,
            resp_get_bucket_encr_2,
        ]

        table = AwsS3Bucket()
        data = table.get_data()

        self.assertIn(['us-west-2', 'test2', '2020-01-02T03:04:05', 2020, 1, 2, 3, 4, 5, 'test1', 123, 'AES256'], data)
        self.assertIn(['us-east-1', 'test3', '2019-01-07T08:09:10', 2019, 1, 7, 8, 9, 10, 'test1', 123, None], data)
        self.assertEqual(len(data), 2)

    def test_aws_ec2_region(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp_describe_regions = [('us-west-2', {'Regions': [
            {'Endpoint': 'ep-1', 'RegionName': 'region-1', 'OptInStatus': 'opt-in-not-required'},
            {'Endpoint': 'ep-2', 'RegionName': 'region-2', 'OptInStatus': 'opted-in'},
            {'Endpoint': 'ep-3', 'RegionName': 'region-3', 'OptInStatus': 'not-opted-in'}
        ]})]
        mock_aws.side_effect = [resp_describe_regions]

        table = AwsEc2Region()
        data = table.get_data()

        self.assertIn(['region-1', 'ep-1', 'opt-in-not-required'], data)
        self.assertIn(['region-2', 'ep-2', 'opted-in'], data)
        self.assertIn(['region-3', 'ep-3', 'not-opted-in'], data)
        self.assertEqual(len(data), 3)

    def test_aws_ec2_key_pair(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp_describe_key_pairs = [
            ('region-1', {'KeyPairs': [
                {'KeyPairId': 'id-1', 'KeyFingerprint': 'fp-1', 'KeyName': 'name-1'},
                {'KeyPairId': 'id-2', 'KeyFingerprint': 'fp-2', 'KeyName': 'name-2'}
            ]}),
            ('region-2', {'KeyPairs': [
                {'KeyPairId': 'id-3', 'KeyFingerprint': 'fp-3', 'KeyName': 'name-3'},
            ]}),
        ]
        mock_aws.side_effect = [resp_describe_key_pairs]

        table = AwsEc2KeyPair()
        data = table.get_data()

        self.assertIn(['region-1', 'name-1', 'id-1', 'fp-1'], data)
        self.assertIn(['region-1', 'name-2', 'id-2', 'fp-2'], data)
        self.assertIn(['region-2', 'name-3', 'id-3', 'fp-3'], data)
        self.assertEqual(len(data), 3)

    def test_aws_ec2_instance(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp_describe_instances = [('us-west-2', {'Reservations': [{
            'Instances': [
                {
                    'ImageId': 'image-1',
                    'InstanceId': 'id-1',
                    'InstanceType': 't1.micro',
                    'KernelId': 'id-2',
                    'KeyName': 'name-1',
                    'LaunchTime': dt.fromisoformat('2020-01-02T03:04:05'),
                    'Platform': 'Windows',
                    'State': {
                        'Code': 123,
                        'Name': 'running'
                    },
                    'IamInstanceProfile': {
                        'Arn': 'arn-1',
                        'Id': 'id-3'
                    },
                },
            ],
            'OwnerId': 'id-4',
        }]})]
        mock_aws.side_effect = [resp_describe_instances]

        table = AwsEc2Instance()
        data = table.get_data()

        self.assertIn([
            'us-west-2', 'id-1', 'running', 123, 't1.micro', 'image-1',
            'id-2', 'name-1', '2020-01-02T03:04:05', 2020, 1, 2, 3, 4, 5,
            'Windows', 'arn-1', 'id-3', 'id-4'
        ], data)
        self.assertEqual(len(data), 1)

    def test_aws_ec2_network_interface(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp = [('us-west-2', {'NetworkInterfaces': [{
            'Association': {
                'PublicDnsName': 't1',
                'PublicIp': 't2'
            },
            'Attachment': {
                'InstanceId': 't3',
            },
            'InterfaceType': 'interface',
            'MacAddress': 't4',
            'NetworkInterfaceId': 't5',
            'PrivateDnsName': 't6',
            'PrivateIpAddress': 't7',
            'PrivateIpAddresses': [
                {
                    'Association': {
                        'PublicDnsName': 't1',
                        'PublicIp': 't2'
                    },
                    'Primary': True,
                    'PrivateDnsName': 't6',
                    'PrivateIpAddress': 't7'
                },
                {
                    'Association': {
                        'PublicDnsName': 't8',
                        'PublicIp': 't9'
                    },
                    'Primary': False,
                    'PrivateDnsName': 't10',
                    'PrivateIpAddress': 't11'
                },
            ],
            'SourceDestCheck': False,
            'SubnetId': 't12',
            'VpcId': 't13'
        }]})]
        mock_aws.side_effect = [resp]

        table = AwsEc2NetworkInterface()
        data = table.get_data()

        self.assertIn([
            'us-west-2', 't5', 'interface', 't3', 't12', 't13', 't6', 't7',
            't1', 't2', True, 't4', False
        ], data)
        self.assertIn([
            'us-west-2', 't5', 'interface', 't3', 't12', 't13', 't10', 't11',
            't8', 't9', False, 't4', False
        ], data)
        self.assertEqual(len(data), 2)

    def test_aws_ec2_instance_security_group(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp = [('us-west-2', {'Reservations': [{
            'Instances': [
                {
                    'InstanceId': 'id-1',
                    'SecurityGroups': [
                        {
                            'GroupName': 'id-2',
                            'GroupId': 'id-3'
                        },
                        {
                            'GroupName': 'id-4',
                            'GroupId': 'id-5'
                        },
                    ],
                },
                {
                    'InstanceId': 'id-6',
                    'SecurityGroups': [
                        {
                            'GroupName': 'id-7',
                            'GroupId': 'id-8'
                        },
                        {
                            'GroupName': 'id-9',
                            'GroupId': 'id-10'
                        },
                    ],
                },
            ],
        }]})]
        mock_aws.side_effect = [resp]

        table = AwsEc2InstanceSecurityGroup()
        data = table.get_data()

        self.assertIn(['us-west-2', 'id-1', 'id-3', 'id-2'], data)
        self.assertIn(['us-west-2', 'id-1', 'id-5', 'id-4'], data)
        self.assertIn(['us-west-2', 'id-6', 'id-8', 'id-7'], data)
        self.assertIn(['us-west-2', 'id-6', 'id-10', 'id-9'], data)
        self.assertEqual(len(data), 4)

    def test_aws_ec2_security_group_rule(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp = [('us-west-2', {'SecurityGroups': [{
            'GroupName': 't1',
            'IpPermissions': [
                {
                    'FromPort': 12,
                    'IpProtocol': 't2',
                    'IpRanges': [
                        {
                            'CidrIp': 't3',
                        },
                        {
                            'CidrIp': 't4',
                        },
                    ],
                    'PrefixListIds': [
                        {
                            'PrefixListId': 't5'
                        },
                    ],
                    'ToPort': 34,
                    'UserIdGroupPairs': [
                        {
                            'GroupId': 't7',
                            'VpcPeeringConnectionId': 't8'
                        },
                    ]
                },
            ],
            'GroupId': 't9',
            'IpPermissionsEgress': [
                {
                    'FromPort': 56,
                    'IpProtocol': 't10',
                    'ToPort': 78,
                    'UserIdGroupPairs': [
                        {
                            'GroupId': 't11',
                            'VpcPeeringConnectionId': 't12'
                        },
                        {
                            'GroupId': 't13',
                            'VpcPeeringConnectionId': 't14'
                        },
                    ]
                },
            ],
            'VpcId': 't15'
        }]})]
        mock_aws.side_effect = [resp]

        table = AwsEc2SecurityGroupRule()
        data = table.get_data()

        self.assertIn(['us-west-2', 't15', 't9', 't1', 'ingress', 't2', 't3', None, None, None, 12, 34], data)
        self.assertIn(['us-west-2', 't15', 't9', 't1', 'ingress', 't2', 't4', None, None, None, 12, 34], data)
        self.assertIn(['us-west-2', 't15', 't9', 't1', 'ingress', 't2', None, 't5', None, None, 12, 34], data)
        self.assertIn(['us-west-2', 't15', 't9', 't1', 'ingress', 't2', None, None, 't7', 't8', 12, 34], data)
        self.assertIn(['us-west-2', 't15', 't9', 't1', 'egress', 't10', None, None, 't11', 't12', 56, 78], data)
        self.assertIn(['us-west-2', 't15', 't9', 't1', 'egress', 't10', None, None, 't13', 't14', 56, 78], data)
        self.assertEqual(len(data), 6)

    def test_aws_vpc(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp = [('us-west-2', {'Vpcs': [{
            'CidrBlock': 't1',
            'DhcpOptionsId': 't2',
            'VpcId': 't3',
            'CidrBlockAssociationSet': [
                {
                    'CidrBlock': 't1',
                },
                {
                    'CidrBlock': 't4',
                },
            ],
            'IsDefault': True,
        }]})]
        mock_aws.side_effect = [resp]

        table = AwsVpc()
        data = table.get_data()

        self.assertIn(['us-west-2', 't3', 't1', 't2', True], data)
        self.assertIn(['us-west-2', 't3', 't4', 't2', True], data)
        self.assertEqual(len(data), 2)

    def test_aws_vpc_peering_connection(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp = [('us-west-2', {'VpcPeeringConnections': [
            {
                'AccepterVpcInfo': {
                    'CidrBlock': 't1',
                    'CidrBlockSet': [
                        {
                            'CidrBlock': 't1'
                        },
                        {
                            'CidrBlock': 't2'
                        },
                    ],
                    'OwnerId': 't3',
                    'VpcId': 't4',
                    'Region': 't5'
                },
                'RequesterVpcInfo': {
                    'CidrBlock': 't6',
                    'OwnerId': 't7',
                    'VpcId': 't8',
                    'Region': 't9'
                },
                'Status': {
                    'Code': 'active',
                },
                'VpcPeeringConnectionId': 't10'
            },
            {
                'AccepterVpcInfo': {
                    'CidrBlock': 't1',
                    'CidrBlockSet': [
                        {
                            'CidrBlock': 't1'
                        },
                        {
                            'CidrBlock': 't2'
                        },
                    ],
                    'OwnerId': 't3',
                    'VpcId': 't4',
                    'Region': 't5'
                },
                'RequesterVpcInfo': {
                    'CidrBlockSet': [
                        {
                            'CidrBlock': 't11'
                        },
                        {
                            'CidrBlock': 't12'
                        },
                    ],
                    'OwnerId': 't13',
                    'VpcId': 't14',
                    'Region': 't15'
                },
                'Status': {
                    'Code': 'deleted',
                },
                'VpcPeeringConnectionId': 't16'
            },
        ]})]
        mock_aws.side_effect = [resp]

        table = AwsVpcPeeringConnection()
        data = table.get_data()

        self.assertIn(['t10', 't7', 't9', 't8', 't6', 't3', 't5', 't4', 't1', 'active'], data)
        self.assertIn(['t10', 't7', 't9', 't8', 't6', 't3', 't5', 't4', 't2', 'active'], data)
        self.assertIn(['t16', 't13', 't15', 't14', 't11', 't3', 't5', 't4', 't1', 'deleted'], data)
        self.assertIn(['t16', 't13', 't15', 't14', 't11', 't3', 't5', 't4', 't2', 'deleted'], data)
        self.assertIn(['t16', 't13', 't15', 't14', 't12', 't3', 't5', 't4', 't1', 'deleted'], data)
        self.assertIn(['t16', 't13', 't15', 't14', 't12', 't3', 't5', 't4', 't2', 'deleted'], data)
        self.assertEqual(len(data), 6)

    def test_aws_subnet(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp = [('us-west-2', {'Subnets': [{
            'AvailabilityZone': 't1',
            'AvailabilityZoneId': 't2',
            'AvailableIpAddressCount': 123,
            'CidrBlock': 't3',
            'DefaultForAz': True,
            'MapPublicIpOnLaunch': False,
            'SubnetId': 't4',
            'VpcId': 't5',
        }]})]
        mock_aws.side_effect = [resp]

        table = AwsVpcSubnet()
        data = table.get_data()

        self.assertIn(['us-west-2', 't4', 't5', 't3', True, False, 123, 't1', 't2'], data)
        self.assertEqual(len(data), 1)

    def test_aws_elastic_ip(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp = [('us-west-2', {'Addresses': [
            {
                'InstanceId': 't1',
                'PublicIp': 't2',
                'AllocationId': 't3',
                'AssociationId': 't4',
                'Domain': 'vpc',
                'NetworkInterfaceId': 't5',
                'NetworkInterfaceOwnerId': 't6',
                'PrivateIpAddress': 't7',
            },
            {
                'InstanceId': None,
                'PublicIp': 't8',
                'AllocationId': 't9',
                'AssociationId': None,
                'Domain': 'standard',
                'NetworkInterfaceId': 't10',
                'NetworkInterfaceOwnerId': 't11',
                'PrivateIpAddress': None,
            },
        ]})]
        mock_aws.side_effect = [resp]

        table = AwsElasticIp()
        data = table.get_data()

        self.assertIn(['us-west-2', 't2', 't7', 't1', 't5', 't6', 't3', 't4', 'vpc'], data)
        self.assertIn(['us-west-2', 't8', None, None, 't10', 't11', 't9', None, 'standard'], data)
        self.assertEqual(len(data), 2)

    def test_aws_image(self, mock_aws, mock_region, mock_client):
        mock_region.return_value = default_region
        mock_client.return_value = test_client
        resp = [('us-west-2', {'Images': [{
            'Architecture': 'x86_64',
            'CreationDate': dt.fromisoformat('2020-01-02T03:04:05'),
            'ImageId': 't1',
            'ImageLocation': 't2',
            'ImageType': 'machine',
            'Public': True,
            'KernelId': 't3',
            'OwnerId': 't4',
            'State': 'available',
            'Name': 't5',
            'RootDeviceName': 't6',
            'RootDeviceType': 'ebs',
            'VirtualizationType': 'hvm'
        }]})]
        mock_aws.side_effect = [resp]

        table = AwsImage()
        data = table.get_data()

        self.assertIn(['us-west-2', 't1', 't5', 't2', 'machine', 'x86_64', '2020-01-02T03:04:05', 2020, 1, 2, 3, 4, 5, True, 't3', 't4', 'available', 't6', 'ebs', 'hvm'], data)
        self.assertEqual(len(data), 1)
