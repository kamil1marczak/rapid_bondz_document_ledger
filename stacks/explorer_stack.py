import os
import json

from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_rds as rds,
    aws_iam as iam,
    aws_s3 as s3,
    aws_route53 as r53,
    aws_route53_targets as r53_targets,
    aws_certificatemanager as cm,
    aws_elasticloadbalancingv2_actions as elbv2_actions,
    aws_elasticloadbalancingv2 as elbv2,
    aws_secretsmanager as sm,
    aws_ecr_assets as ecr_assets,
    aws_elasticloadbalancingv2 as elbv2,
    aws_apigateway as agw,
    aws_lambda as _lambda,
    aws_ecs_patterns as ecs_patterns,
    RemovalPolicy, Duration, Aws, Stack, CfnOutput, Environment, Fn, Duration,
)
from constructs import Construct

with open(os.path.join(os.getcwd(), "cdk.out/data/cloud9.json")) as cloud9_json:
    cloud9_data = json.load(cloud9_json)
    cloud9_json.close()


class ExplorerStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self._availability_zones = self.availability_zones

        self.default_vpc = ec2.Vpc.from_lookup(
            self, "DefaultVpc",
            is_default=True,
        )

        self.database_subnets = [
            ec2.Subnet(
                self, "DatabaseSubnet0",
                vpc_id=self.default_vpc.vpc_id,
                cidr_block="172.31.160.0/20",
                availability_zone=self._availability_zones[0],
            ),

            ec2.Subnet(
                self, "DatabaseSubnet1",
                vpc_id=self.default_vpc.vpc_id,
                cidr_block="172.31.176.0/20",
                availability_zone=self._availability_zones[1],
            ),

            ec2.Subnet(
                self, "DatabaseSubnet2",
                vpc_id=self.default_vpc.vpc_id,
                cidr_block="172.31.192.0/20",
                availability_zone=self._availability_zones[2],
            )
        ]

        self.database_username = "explorer"

        self.database_password_secret = sm.Secret.from_secret_attributes(
            self, 'DatabasePassword',
            secret_complete_arn=Fn.import_value('DocumentLedgerExplorerDatabasePasswordArn'),
        )

        self.database = rds.DatabaseInstance(
            self, "Database",
            engine=rds.DatabaseInstanceEngine.postgres(version=rds.PostgresEngineVersion.VER_12_3),
            instance_type=ec2.InstanceType.of(ec2.InstanceClass.BURSTABLE2, ec2.InstanceSize.SMALL),
            vpc=self.default_vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnets=self.database_subnets,
            ),
            publicly_accessible=False,
            credentials=rds.Credentials.from_password(self.database_username,
                                                      self.database_password_secret.secret_value)
        )

        self.cloud9_security_group = ec2.SecurityGroup.from_security_group_id(
            self, 'Cloud9SecurityGroup',
            cloud9_data["securityGroupId"])

        self.database.connections.allow_default_port_from(self.cloud9_security_group)

        self.image_directory = os.path.join(os.getcwd(), "explorer")

        self.image_asset = ecr_assets.DockerImageAsset(
            self, "Image",
            directory=self.image_directory,
        )

        self.image = ecs.ContainerImage.from_docker_image_asset(self.image_asset)

        self.domain_name = f"explorer.{os.getenv('LEDGER_DOMAIN_NAME', default='')}"

        self.domain_zone = r53.PublicHostedZone(
            self, "HostedZone",
            zone_name=self.domain_name,
        )

        self.base_zone = r53.PublicHostedZone.from_hosted_zone_attributes(
            self, "BaseZone",
            hosted_zone_id=Fn.import_value("DocumentLedgerHostedZoneId"),
            zone_name=os.getenv('LEDGER_DOMAIN_NAME', default='')
        )

        r53.NsRecord(
            self, "DelegationRecord",
            zone=self.base_zone,
            record_name='explorer',
            values=self.domain_zone.hosted_zone_name_servers or [],
        )

        self.validation = cm.CertificateValidation.from_dns(self.domain_zone)

        self.certificate = cm.Certificate(
            self, 'Certificate',
            domain_name=self.domain_name,
            validation=self.validation
        )

        self.service_subnets = [
            ec2.Subnet(
                self, "ServiceSubnet0",
                vpc_id=self.default_vpc.vpc_id,
                cidr_block="172.31.208.0/20",
                availability_zone=self._availability_zones[0],
            ),

            ec2.Subnet(
                self, "ServiceSubnet1",
                vpc_id=self.default_vpc.vpc_id,
                cidr_block="172.31.224.0/20",
                availability_zone=self._availability_zones[1],
            ),

            ec2.Subnet(
                self, "ServiceSubnet2",
                vpc_id=self.default_vpc.vpc_id,
                cidr_block="172.31.240.0/20",
                availability_zone=self._availability_zones[2],
            )
        ]

        self.cluster = ecs.Cluster(
            self, "Cluster",
            vpc=self.default_vpc,
        )

        self.service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self, "Service",
            cluster=self.cluster,
            certificate=self.certificate,
            domain_name=self.domain_name,
            domain_zone=self.domain_zone,
            protocol=elbv2.ApplicationProtocol.HTTPS,
            redirect_http=True,
            task_subnets=ec2.SubnetSelection(
                subnets=self.service_subnets,
            ),
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=self.image,
                container_port=8080,
                environment={
                    "DATABASE_HOST": self.database.instance_endpoint.hostname,
                    "DATABASE_USERNAME": self.database_username,
                    "DATABASE_PASSWD": self.database_password_secret.secret_value.to_string(),
                    "LOG_LEVEL_APP": 'debug',
                    "LOG_LEVEL_DB": 'debug',
                    "LOG_LEVEL_CONSOLE": 'debug',
                    "LOG_CONSOLE_STDOUT": 'true',
                    "DISCOVERY_AS_LOCALHOST": 'false',
                }
            )
        )

        self.database.connections.allow_default_port_from(self.service.service)

        self.ledger_port_range = ec2.Port.tcp_range(30001, 30004)
        self.ledger_security_group_id = Fn.import_value("DocumentLedgerDefaultVpcEndpointSecurityGroup")
        self.ledger_security_group = ec2.SecurityGroup.from_security_group_id(
            self, 'DefaultVpcEndpointSecurityGroup',
            security_group_id=self.ledger_security_group_id
        )

        self.ledger_security_group.connections.allow_from(
            self.service.service,
            port_range=self.ledger_port_range,
        )

        self.cloud_watch_logs_vpc_endpoint = ec2.InterfaceVpcEndpoint(
            self, 'CloudWatchLogsEndpoint',
            vpc=self.default_vpc,
            subnets=ec2.SubnetSelection(
                subnets=self.service_subnets,
            ),
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS
        )

        self.cloud_watch_logs_vpc_endpoint.connections.allow_default_port_from(self.cluster)

        self.ecr_vpc_endpoint = ec2.InterfaceVpcEndpoint(
            self, 'EcrEndpoint',
            vpc=self.default_vpc,
            subnets=ec2.SubnetSelection(
                subnets=self.service_subnets,
            ),
            service=ec2.InterfaceVpcEndpointAwsService.ECR
        )

        self.ecr_vpc_endpoint.connections.allow_default_port_from(self.cluster)

        self.ecr_docker_vpc_endpoint = ec2.InterfaceVpcEndpoint(
            self, 'EcrDockerEndpoint',
            vpc=self.default_vpc,
            subnets=ec2.SubnetSelection(
                subnets=self.service_subnets,
            ),
            service=ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
        )

        self.ecr_docker_vpc_endpoint.connections.allow_default_port_from(self.cluster)

        ec2.GatewayVpcEndpoint(
            self, 'S3Endpoint',
            vpc=self.default_vpc,
            subnets=[ec2.SubnetSelection(
                subnets=self.service_subnets,
            )],
            service=ec2.GatewayVpcEndpointAwsService.S3,
        )

        CfnOutput(
            self, 'ExplorerImageUri',
            value=self.image_asset.image_uri,
            description="Explorer Docker image URI",
        )

        CfnOutput(
            self, 'DatabaseHostname',
            value=self.database.instance_endpoint.hostname,
            description='Database hostname',
        )

        CfnOutput(
            self, 'ExplorerUrl',
            value=f"https://{self.domain_name}",
            description='Explorer user interface URL',
        )

"""

    new ec2.GatewayVpcEndpoint(this, 'S3Endpoint', {
      vpc: defaultVpc,
      subnets: [{subnets: serviceSubnets}],
      service: ec2.GatewayVpcEndpointAwsService.S3,
    });

    new cdk.CfnOutput(this, 'ExplorerImageUri', {
      value: imageAsset.imageUri,
      description: 'Explorer Docker image URI',
    });

    new cdk.CfnOutput(this, 'DatabaseHostname', {
      value: database.instanceEndpoint.hostname,
      description: 'Database hostname',
    });

    new cdk.CfnOutput(this, 'ExplorerUrl', {
      value: `https://${domainName}`,
      description: 'Explorer user interface URL',
    });

  }

}

"""
