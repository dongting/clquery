# clquery: SQL interface to your cloud resources

## One-liner
`clquery` allows you to perform live queries on your cloud resources, and use the power of SQL to combine and filter across multiple types of services and resources.

## Install
```shell
$ virtualenv venv && source venv/bin/activate
$ pip install clquery
$ clquery
clquery> .tables
```

## Example queries
See all AWS elastic IPs in `us-west-2` region and their associated EC2 instances:
```sql
SELECT public_ip, instance_id
FROM aws_elastic_ip
WHERE region='us-west-2';
```

See all non-default VPCs and their CIDRs in all regions:
```sql
SELECT region, vpc_id, cidr
FROM aws_vpc
WHERE is_default is FALSE;
```

Find EC2 instances in `us-west-2` region that have a Security Group rule that is open to the world:
```sql
SELECT
  vm.instance_id,
  sgr.ip_range,
  sgr.ip_protocol,
  sgr.from_port,
  sgr.to_port
FROM aws_ec2_instance as vm
JOIN aws_ec2_instance_security_group isg USING(instance_id)
JOIN aws_ec2_security_group_rule sgr USING(security_group_id)
WHERE vm.region='us-west-2'
  AND sgr.direction='ingress'
  AND sgr.ip_range='0.0.0.0/0';
```

## Other trivia
- The SQL engine is powered by [SQLite](https://sqlite.org/) and [APSW](https://github.com/rogerbinns/apsw) through [Virtual Tables](https://sqlite.org/vtab.html)
- The shell is also (almost) a SQLite shell, and dot commands will work (e.g. `.tables`)


## Inspiration and reality
The goal is to support mainstream services on major cloud providers. However, it currently only supports AWS for a few services.

This project is inspired by [osquery](https://osquery.io/).
