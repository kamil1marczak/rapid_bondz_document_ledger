#!/usr/bin/env python3


import os

# Import specific constructs groups from aws_cdk according to our needs
from aws_cdk import (
    App, Environment
)

from stacks.foundation_stack import FoundationStack
from stacks.ledger_stack import LedgerStack
from stacks.interface_stack import InterfaceStack
from stacks.explorer_stack import ExplorerStack


app = App()

env = Environment(account="213558450385", region="us-east-1")

FoundationStack(app, "FoundationStack", env=env)

LedgerStack(app, "LedgerStack", env=env)

InterfaceStack(app, "InterfaceStack", env=env)

ExplorerStack(app, "ExplorerStack", env=env)


app.synth()
