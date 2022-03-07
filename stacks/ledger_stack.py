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
    aws_managedblockchain as managedblockchain,
    aws_ecs_patterns as ecs_patterns,
    RemovalPolicy, Duration, Aws, Stack, CfnOutput, Fn,
)
from constructs import Construct


class LedgerStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.admin_password_secret = sm.Secret.from_secret_attributes(
          self, "AdminPassword",
          secret_complete_arn= Fn.import_value("DocumentLedgerAdminPasswordArn")
        )

        self.admin_password = self.admin_password_secret.secret_value.to_string()

        self.network_name = 'LedgerNetwork'
        self.member_name = 'LedgerMember'

        # self.network_configuration = managedblockchain.CfnMember.NetworkConfigurationProperty(
        #   name=self.network_name,
        #   description="networkName",
        #   framework="HYPERLEDGER_FABRIC",
        #   framework_version="1.4",
        #   network_framework_configuration=managedblockchain.CfnMember.NetworkFrameworkConfigurationProperty(
        #     network_fabric_configuration=managedblockchain.CfnMember.NetworkFabricConfigurationProperty(
        #       edition="STARTER"
        #     ),
        #   ),
        #   voting_policy=managedblockchain.CfnMember.VotingPolicyProperty(
        #     approval_threshold_policy=managedblockchain.CfnMember.ApprovalThresholdPolicyProperty(
        #       proposal_duration_in_hours=24,
        #       threshold_percentage=50,
        #       threshold_comparator="GREATER_THAN",
        #     )
        #   )
        # )

        self.network_configuration = managedblockchain.CfnMember.NetworkConfigurationProperty(
            framework="HYPERLEDGER_FABRIC",
            framework_version="1.4",
            name=self.network_name,
            voting_policy=managedblockchain.CfnMember.VotingPolicyProperty(
                approval_threshold_policy=managedblockchain.CfnMember.ApprovalThresholdPolicyProperty(
                    proposal_duration_in_hours=24,
                    threshold_comparator="GREATER_THAN",
                    threshold_percentage=50
                )
            ),

            # the properties below are optional
            description="networkName",
            network_framework_configuration=managedblockchain.CfnMember.NetworkFrameworkConfigurationProperty(
                network_fabric_configuration=managedblockchain.CfnMember.NetworkFabricConfigurationProperty(
                    edition="STARTER"
                )
            )
        )

        # self.member_configuration = managedblockchain.CfnMember.MemberConfigurationProperty(
        #   name="memberName",
        #
        #   # the properties below are optional
        #   description="memberName",
        #   member_framework_configuration=managedblockchain.CfnMember.MemberFrameworkConfigurationProperty(
        #     member_fabric_configuration=managedblockchain.CfnMember.MemberFabricConfigurationProperty(
        #       admin_password="adminPassword",
        #       admin_username="admin"
        #     )
        #   )
        # )

        self.member_configuration = managedblockchain.CfnMember.MemberConfigurationProperty(
            name="memberName",

            # the properties below are optional
            description="memberName",
            member_framework_configuration=managedblockchain.CfnMember.MemberFrameworkConfigurationProperty(
                member_fabric_configuration=managedblockchain.CfnMember.MemberFabricConfigurationProperty(
                    admin_password=self.admin_password,
                    admin_username="admin"
                )
            )
        )

        self.network = managedblockchain.CfnMember(
          self, "DocumentLedger",
          network_configuration=self.network_configuration,
          member_configuration=self.member_configuration,
        )

        self.network_id = self.network.get_att("NetworkId").to_string()
        self.member_id = self.network.get_att("MemberId").to_string()

        self._node = managedblockchain.CfnNode(
          self, "DocumentLedgerNode",
          network_id=self.network_id,
          member_id=self.member_id,
          node_configuration=managedblockchain.CfnNode.NodeConfigurationProperty(
            availability_zone="us-east-1a",
            instance_type="bc.t3.small"
          ),
        )

        self._node_id = self._node.get_att("NodeId").to_string()

        CfnOutput(
          self, "NetworkName",
          value=self.network_name,
          description="Managed Blockchain network name"
        )

        CfnOutput(
          self, "MemberName",
          value=self.member_name,
          description="Managed Blockchain member name"
        )

        CfnOutput(
          self, "NetworkId",
          value=self.network_id,
          description="Managed Blockchain network identifier"
        )

        CfnOutput(
          self, "MemberId",
          value=self.member_id,
          description="Managed Blockchain member identifier"
        )

        CfnOutput(
          self, "NodeId",
          value=self._node_id,
          description="Managed Blockchain node identifier"
        )
