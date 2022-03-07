ACCOUNT_ID ?= "213558450385"
REGION ?= "us-east-1"

login_ecr:
	@aws ecr get-login-password --region $(REGION) || docker login --username AWS --password-stdin $(ACCOUNT_ID).dkr.ecr.$(REGION).amazonaws.com

login_public:
	@aws ecr-public get-login-password --region us-east-1 || docker login --username AWS --password-stdin public.ecr.aws

update_dep:
	pip install pip-tools
	pip-compile ./requirements/requirements.in --output-file ./requirements/requirements.txt
	pip install -r ./requirements/requirements.txt
	#pip-compile --generate-hashes diagram_generate_lambda/requirements/requirements.in --output-file diagram_generate_lambda/requirements/requirements.txt


