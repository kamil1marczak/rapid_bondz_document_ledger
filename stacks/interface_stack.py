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
    aws_apigateway as agw,
    aws_lambda as _lambda,
    aws_ecs_patterns as ecs_patterns,
    RemovalPolicy, Duration, Aws, Stack, CfnOutput, Environment, Fn, Duration,
)
from constructs import Construct

# with open("../cdk.out/data/network.json") as network_json:
with open(os.path.join(os.getcwd(), "cdk.out/data/network.json")) as network_json:
    network_data = json.load(network_json)
    network_json.close()

with open(os.path.join(os.getcwd(), "cdk.out/data/member.json")) as member_json:
    member_data = json.load(member_json)
    member_json.close()

with open(os.path.join(os.getcwd(), "cdk.out/data/node.json")) as node_json:
    node_data = json.load(node_json)
    node_json.close()

with open(os.path.join(os.getcwd(), "cdk.out/data/cloud9.json")) as cloud9_json:
    cloud9_data = json.load(cloud9_json)
    cloud9_json.close()


class InterfaceStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # # self._account = env.account
        # self._account = self.account
        # # self._region = env.region
        # self._region = self.region

        self.domain_name = f"api.{os.getenv('LEDGER_DOMAIN_NAME', default='')}"
        self.domain_zone = r53.PublicHostedZone(
            self, "HostedZone",
            zone_name=self.domain_name
        )

        self.base_zone = r53.PublicHostedZone.from_hosted_zone_attributes(
            self, "BaseZone",
            hosted_zone_id=Fn.import_value("DocumentLedgerHostedZoneId"),
            zone_name=os.getenv('LEDGER_DOMAIN_NAME', default='')
        )

        r53.NsRecord(
            self, "DelegationRecord",
            zone=self.base_zone,
            record_name="api",
            values=self.domain_zone.hosted_zone_name_servers or []
        )

        self.validation = cm.CertificateValidation.from_dns(self.domain_zone)
        self.certificate = cm.Certificate(
            self, "Certificate",
            domain_name=self.domain_name,
            validation=self.validation,
        )

        self.api_vpc = ec2.Vpc(
            self, "ApiVpc",
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                    name="Lambdas",
                    # cidr_mask=24
                )
            ]
        )

        self.api_reader_token_arn = Fn.import_value("DocumentLedgerApiReaderTokenArn")
        self.api_writer_token_arn = Fn.import_value("DocumentLedgerApiWriterTokenArn")

        self.api_reader_token = sm.Secret.from_secret_attributes(
            self, "ApiReaderToken",
            secret_complete_arn=self.api_reader_token_arn
        )

        self.api_writer_token = sm.Secret.from_secret_attributes(
            self, "ApiWriterToken",
            secret_complete_arn=self.api_writer_token_arn
        )

        self.admin_private_key_arn = Fn.import_value("DocumentLedgerAdminPrivateKeyArn")
        self.admin_signed_cert_arn = Fn.import_value("DocumentLedgerAdminSignedCertArn")

        self.admin_private_key = sm.Secret.from_secret_attributes(
            self, "AdminPrivateKey",
            secret_complete_arn=self.admin_private_key_arn
        )

        self.admin_signed_cert = sm.Secret.from_secret_attributes(
            self, "AdminSignedCert",
            secret_complete_arn=self.admin_signed_cert_arn
        )

        self._api = agw.RestApi(
            self, "Api",
            domain_name=agw.DomainNameOptions(
                # self, "DomainName",
                domain_name=self.domain_name,
                certificate=self.certificate,
                security_policy=agw.SecurityPolicy.TLS_1_2
            ),

        )

        r53.ARecord(
            self, "ApiDomainRecord",
            zone=self.domain_zone,
            target=r53.RecordTarget.from_alias(
                r53_targets.ApiGateway(self._api))
        )

        self.authorizer_function = _lambda.Function(
            self, "ApiAuthorizerFunction",
            runtime=_lambda.Runtime.NODEJS_14_X,
            code=_lambda.AssetCode.from_asset(
                os.path.join(os.getcwd(), "lambdas/authorizer")
            ),
            handler='index.handler',
            environment={
                "BASE_METHOD_ARN": f"arn:aws:execute-api:{self.region}:{self.account}:{self._api.rest_api_id}",
                "READER_SECRET_ARN": self.api_reader_token_arn,
                "WRITER_SECRET_ARN": self.api_writer_token_arn,
            }
        )

        self.api_reader_token.grant_read(self.authorizer_function)
        self.api_writer_token.grant_write(self.authorizer_function)

        self.api_lambda_layer = _lambda.LayerVersion(
            self, "ApiLambdaLayer",
            compatible_runtimes=[_lambda.Runtime.NODEJS_12_X],
            code=_lambda.AssetCode.from_asset(
                os.path.join(os.getcwd(), "lambdas/layer")
            ),
        )

        self.reader_function = _lambda.Function(
            self, "ApiReaderFunction",
            vpc=self.api_vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnets=self.api_vpc.isolated_subnets,
            ),
            memory_size=256,
            timeout=Duration.seconds(10.0),
            runtime=_lambda.Runtime.NODEJS_12_X,
            layers=[self.api_lambda_layer],
            code=_lambda.AssetCode.from_asset(
                os.path.join(os.getcwd(), "lambdas/reader")
            ),
            handler='index.handler',
            environment={
                "PRIVATE_KEY_ARN": self.admin_private_key_arn,
                "SIGNED_CERT_ARN": self.admin_signed_cert_arn,
                "MEMBER_ID": member_data["Id"],
                "ORDERER_ENDPOINT": network_data["FrameworkAttributes"]["Fabric"]["OrderingServiceEndpoint"],
                "CA_ENDPOINT": member_data["FrameworkAttributes"]["Fabric"]["CaEndpoint"],
                "PEER_ENDPOINT": node_data["FrameworkAttributes"]["Fabric"]["PeerEndpoint"],
                "CHANNEL_NAME": 'documents',
                "CHAINCODE_NAME": 'documents',
            }
        )

        self.writer_function = _lambda.Function(
            self, "ApiWriterFunction",
            vpc=self.api_vpc,
            vpc_subnets=ec2.SubnetSelection(
                subnets=self.api_vpc.isolated_subnets,
            ),
            memory_size=256,
            timeout=Duration.seconds(10.0),
            runtime=_lambda.Runtime.NODEJS_12_X,
            layers=[self.api_lambda_layer],
            code=_lambda.AssetCode.from_asset(
                os.path.join(os.getcwd(), "lambdas/writer")
            ),
            handler='index.handler',
            environment={
                "PRIVATE_KEY_ARN": self.admin_private_key_arn,
                "SIGNED_CERT_ARN": self.admin_signed_cert_arn,
                "MEMBER_ID": member_data["Id"],
                "ORDERER_ENDPOINT": network_data["FrameworkAttributes"]["Fabric"]["OrderingServiceEndpoint"],
                "CA_ENDPOINT": member_data["FrameworkAttributes"]["Fabric"]["CaEndpoint"],
                "PEER_ENDPOINT": node_data["FrameworkAttributes"]["Fabric"]["PeerEndpoint"],
                "CHANNEL_NAME": 'documents',
                "CHAINCODE_NAME": 'documents',
            }
        )

        self.admin_private_key.grant_read(self.reader_function)
        self.admin_private_key.grant_read(self.writer_function)
        self.admin_signed_cert.grant_read(self.reader_function)
        self.admin_signed_cert.grant_read(self.writer_function)

        self.secrets_manager_vpc_endpoint = ec2.InterfaceVpcEndpoint(
            self, "SecretsManagerEndpoint",
            vpc=self.api_vpc,
            service=ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER
        )

        self.secrets_manager_vpc_endpoint.connections.allow_default_port_from(self.reader_function)
        self.secrets_manager_vpc_endpoint.connections.allow_default_port_from(self.writer_function)

        self.ledger_port_range = ec2.Port.tcp_range(30001, 30004)

        ledger_vpc_endpoint_name = str(network_data["VpcEndpointServiceName"])
        ledger_vpc_endpoint_name.replace(f"com.amazonaws.{self.region}.", "")
        self.ledger_vpc_endpoint_name = ledger_vpc_endpoint_name
        # self.ledger_vpc_endpoint_name = 'managedblockchain.n-a5gn4yuvkjf43a57eeyf5w3h7u'

        self.api_vpc_endpoint = ec2.InterfaceVpcEndpoint(
            self, "LedgerEndpoint",
            vpc=self.api_vpc,
            service=ec2.InterfaceVpcEndpointAwsService(self.ledger_vpc_endpoint_name),
            open=False,
        )

        self.api_vpc_endpoint.connections.allow_from(self.reader_function, self.ledger_port_range)
        self.api_vpc_endpoint.connections.allow_from(self.writer_function, self.ledger_port_range)

        self.authorizer = agw.TokenAuthorizer(
            self, "TokenAuthorizer",
            handler=self.authorizer_function,
        )

        self.reader = agw.LambdaIntegration(self.reader_function)
        self.writer = agw.LambdaIntegration(self.writer_function)

        self.documents = self._api.root.add_resource('documents')
        self.documents.add_method("GET", self.reader, authorizer=self.authorizer)
        self.documents.add_method("POST", self.writer, authorizer=self.authorizer)

        self.document = self.documents.add_resource('{document_id}')

        self.document.add_method("GET", self.reader, authorizer=self.authorizer)
        self.document.add_method("POST", self.writer, authorizer=self.authorizer)
        self.document.add_method("DELETE", self.writer, authorizer=self.authorizer)

        self.cloud9_security_group = ec2.SecurityGroup.from_security_group_id(
            self, "Cloud9SecurityGroup",
            security_group_id=cloud9_data["securityGroupId"]

        )

        self.default_vpc = ec2.Vpc.from_lookup(
            self, "DefaultVpc",
            is_default=True,
        )


        self.default_vpc_endpoint = ec2.InterfaceVpcEndpoint(
            self, "DefaultVpcEndpoint",
            vpc=self.default_vpc,
            service = ec2.InterfaceVpcEndpointAwsService(self.ledger_vpc_endpoint_name),
            open=False,
        )

        self.default_vpc_endpoint.connections.allow_from(self.cloud9_security_group, self.ledger_port_range)

        CfnOutput(
            self, "DefaultVpcEndpointSecurityGroup",
            value=self.default_vpc_endpoint.connections.security_groups[0].security_group_id,
            export_name="DocumentLedgerDefaultVpcEndpointSecurityGroup",
            description="Security group associated with the VPC endpoint used to connect to the ledger",
        )

        CfnOutput(
            self, "ApiEndpointUrl",
            value=f"https://{self.domain_name}",
            description="API Gateway endpoint URL",
        )

"""

    const cloud9SecurityGroup = ec2.SecurityGroup.fromSecurityGroupId(this, 'Cloud9SecurityGroup', cloud9Data.securityGroupId);
    const defaultVpc = ec2.Vpc.fromLookup(this, 'DefaultVpc', {isDefault: true});
    const defaultVpcEndpoint = new ec2.InterfaceVpcEndpoint(this, 'DefaultVpcEndpoint', {
      vpc: defaultVpc,
      service: new ec2.InterfaceVpcEndpointAwsService(ledgerVpcEndpointName),
      open: false,
    });
    defaultVpcEndpoint.connections.allowFrom(cloud9SecurityGroup, ledgerPortRange);

    new cdk.CfnOutput(this, 'DefaultVpcEndpointSecurityGroup', {
      value: defaultVpcEndpoint.connections.securityGroups[0].securityGroupId,
      exportName: 'DocumentLedgerDefaultVpcEndpointSecurityGroup',
      description: 'Security group associated with the VPC endpoint used to connect to the ledger',
    });

    new cdk.CfnOutput(this, 'ApiEndpointUrl', {
      value: `https://${domainName}`,
      description: 'API Gateway endpoint URL',
    });

  }

}


"""
