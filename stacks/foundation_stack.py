import os

from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_rds as rds,
    aws_iam as iam,
    aws_s3 as s3,
    aws_route53 as r53,
    aws_elasticloadbalancingv2_actions as elbv2_actions,
    aws_elasticloadbalancingv2 as elbv2,
    aws_secretsmanager as sm,
    aws_ecs_patterns as ecs_patterns,
    RemovalPolicy, Duration, Aws, Stack, CfnOutput,
)
from constructs import Construct


class FoundationStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # self.tokenRequirements = {
        #     "passwordLength": 32,
        #     "requireEachIncludedType": True,
        #     "excludeCharacters": '\'"/\\@&{}<>*|',
        # }
        #
        # self.passwordRequirements = {
        #     "passwordLength": 32,
        #     "requireEachIncludedType": True,
        #     "excludeCharacters": '\'"/\\@&{}<>*|',
        # }
        #
        # self.databasePasswordRequirements = {
        #     "passwordLength": 32,
        #     "requireEachIncludedType": True,
        #     "excludePunctuation": True,
        # }

        """
        Secret Requirements
        """

        self.token_requirements = sm.SecretStringGenerator(
            password_length=32,
            require_each_included_type=True,
            exclude_characters='\'"/\\@&{}<>*|'
        )

        self.password_requirements = sm.SecretStringGenerator(
            password_length=32,
            require_each_included_type=True,
            exclude_characters='\'"/\\@&{}<>*|'
        )

        self.database_password_requirements = sm.SecretStringGenerator(
            password_length=32,
            require_each_included_type=True,
            exclude_punctuation=True
        )

        """
        Secret Generate
        """

        self.api_reader_token = sm.Secret(
            self, "ApiReaderToken",
            generate_secret_string=self.token_requirements
        )

        self.api_writer_token = sm.Secret(
            self, "ApiWriterToken",
            generate_secret_string=self.token_requirements
        )

        self.admin_password_secret = sm.Secret(
            self, "AdminPassword",
            generate_secret_string=self.password_requirements
        )

        self.admin_private_key_secret = sm.Secret(
            self, 'AdminPrivateKey'
        )

        self.admin_signed_cert_secret = sm.Secret(
            self, 'AdminSignedCert'
        )

        self.explorer_admin_password = sm.Secret(
            self, 'ExplorerAdminPassword',
            generate_secret_string=self.password_requirements
        )

        self.explorer_database_password = sm.Secret(
            self, 'ExplorerDatabasePassword',
            generate_secret_string=self.database_password_requirements
        )

        self.domain_name = os.getenv('LEDGER_DOMAIN_NAME', default="")

        self.domain_zone = r53.PublicHostedZone(
            self, "HostedZone",
            zone_name=self.domain_name
        )

        CfnOutput(
            self, "ApiReaderTokenArn",
            value=self.api_reader_token.secret_full_arn if self.api_reader_token.secret_full_arn else self.api_reader_token.secret_arn,
            export_name="DocumentLedgerApiReaderTokenArn",
            description="Secret ARN for API reader token",
        )

        CfnOutput(
            self, "ApiWriterTokenArn",
            value=self.api_writer_token.secret_full_arn if self.api_writer_token.secret_full_arn else self.api_writer_token.secret_arn,
            export_name="DocumentLedgerApiWriterTokenArn",
            description="Secret ARN for API writer token",
        )

        CfnOutput(
            self, "AdminPasswordArn",
            value=self.admin_password_secret.secret_full_arn if self.admin_password_secret.secret_full_arn else self.admin_password_secret.secret_arn,
            export_name="DocumentLedgerAdminPasswordArn",
            description="Secret ARN for ledger admin password",
        )

        CfnOutput(
            self, "AdminPrivateKeyArn",
            value=self.admin_private_key_secret.secret_full_arn if self.admin_private_key_secret.secret_full_arn else self.admin_private_key_secret.secret_arn,
            export_name="DocumentLedgerAdminPrivateKeyArn",
            description="Seecret ARN for ledger admin private key",
        )

        CfnOutput(
            self, "AdminSignedCertArn",
            value=self.admin_signed_cert_secret.secret_full_arn if self.admin_signed_cert_secret.secret_full_arn else self.admin_signed_cert_secret.secret_arn,
            export_name="DocumentLedgerAdminSignedCertArn",
            description="Secret ARN for ledger admin signed certificate",
        )

        CfnOutput(
            self, "ExplorerAdminPasswordArn",
            value=self.explorer_admin_password.secret_full_arn if self.explorer_admin_password.secret_full_arn else self.explorer_admin_password.secret_arn,
            export_name="DocumentLedgerExplorerAdminPasswordArn",
            description="Secret ARN for explorer admin password",
        )

        CfnOutput(
            self, "ExplorerDatabasePasswordArn",
            value=self.explorer_database_password.secret_full_arn if self.explorer_database_password.secret_full_arn else self.explorer_database_password.secret_arn,
            export_name="DocumentLedgerExplorerDatabasePasswordArn",
            description="Secret ARN for explorer database password",
        )

        CfnOutput(
            self, "HostedZoneId",
            value=self.domain_zone.hosted_zone_id if self.explorer_database_password.secret_full_arn else self.explorer_database_password.secret_arn,
            export_name="DocumentLedgerHostedZoneId",
            description="Hosted zone ID for the base domain",
        )

