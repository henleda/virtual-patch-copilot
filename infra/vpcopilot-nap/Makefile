# vpcopilot-nap — provision + COST CONTROL for the F5 WAF for NGINX (App Protect v4)
# box. Reuses the vpcopilot-lab VPC + Larkspur origin. Every stop/start is scoped to
# Project=$(PROJECT) so it can never touch another estate.
#
#   make check          verify tooling + profile + that the lab VPC exists
#   make plan/apply     stand the box up (Terraform)
#   make onboard JWT=~/Downloads/nginx-one-*.jwt
#                       install NGINX Plus + App Protect over SSM (delivers the JWT)
#   make tunnel         open an SSM port-forward to the box's SSH (127.0.0.1:$(SSH_LOCAL_PORT))
#   make ssh            SSH in over that tunnel (open `make tunnel` in another shell first)
#   make shell          SSM shell on the box
#   make nap-down       STOP the box (kills EC2 hourly; keeps the install)
#   make nap-up         START it again
#   make nap-status     show instance state
#   make nap-nuke       terraform destroy

AWS_PROFILE    ?= vpcopilot
REGION         ?= us-east-2
PROJECT        ?= vpcopilot-nap
LAB_PROJECT    ?= vpcopilot-lab
ORIGIN         ?= 10.30.10.22:8080
SSH_LOCAL_PORT ?= 2223

AWS  := aws --profile $(AWS_PROFILE) --region $(REGION)
TAGF := Name=tag:Project,Values=$(PROJECT)

# The box id, resolved at run time from tags (running only).
NAP_ID = $$($(AWS) ec2 describe-instances --filters "$(TAGF)" "Name=tag:Role,Values=nap" \
	"Name=instance-state-name,Values=running" --query 'Reservations[0].Instances[0].InstanceId' --output text)

.PHONY: check keypair init plan apply onboard tunnel ssh shell nap-status nap-down nap-up nap-nuke whoami

check:
	@echo "profile : $(AWS_PROFILE)"; echo "region  : $(REGION)"
	@command -v terraform >/dev/null && echo "terraform: $$(terraform version | head -1)" || echo "terraform: MISSING"
	@command -v session-manager-plugin >/dev/null && echo "ssm-plugin: present" || echo "ssm-plugin: MISSING (brew install --cask session-manager-plugin)"
	@$(AWS) sts get-caller-identity --query 'Account' --output text >/dev/null 2>&1 \
	  && echo "identity : $$($(AWS) sts get-caller-identity --query 'Account' --output text)" \
	  || { echo "identity : profile '$(AWS_PROFILE)' not logged in — run: aws sso login --profile $(AWS_PROFILE)"; exit 1; }
	@vpc=$$($(AWS) ec2 describe-vpcs --filters "Name=tag:Name,Values=$(LAB_PROJECT)-vpc" \
	  --query 'Vpcs[0].VpcId' --output text 2>/dev/null); \
	  [ "$$vpc" != "None" ] && [ -n "$$vpc" ] \
	  && echo "lab vpc  : $$vpc ($(LAB_PROJECT))" \
	  || echo "lab vpc  : NOT FOUND — stand up ../$(LAB_PROJECT) first (the box reuses its VPC + origin)"

keypair:
	@test -f .secrets/vpcopilot_nap.pub && echo ".secrets/ keypair already present" || { \
	  mkdir -p .secrets && ssh-keygen -t rsa -b 4096 -N '' -f .secrets/vpcopilot_nap.pem \
	  && mv .secrets/vpcopilot_nap.pem.pub .secrets/vpcopilot_nap.pub && echo "generated .secrets/vpcopilot_nap.{pem,pub}"; }

init:
	terraform init

plan: keypair
	terraform plan

apply: keypair
	terraform apply

whoami:
	@$(AWS) sts get-caller-identity --output table

# Ship onboard/nap-onboard.sh + the JWT to the box over SSM and run it. The JWT
# transits SSM (encrypted) and is written to /etc/nginx/license.jwt on the box;
# it never lands in user_data or Terraform state. NOTE: SSM command parameters are
# recorded in CloudTrail — acceptable for a lab; rotate the token from MyF5 if that
# matters to you.
onboard:
	@test -n "$(JWT)" || { echo "usage: make onboard JWT=~/Downloads/nginx-one-*.jwt"; exit 1; }
	@test -f "$(JWT)" || { echo "JWT not found: $(JWT)"; exit 1; }
	@nid=$(NAP_ID); test "$$nid" != "None" -a -n "$$nid" || { echo "no running $(PROJECT) box — make apply / make nap-up"; exit 1; }; \
	echo "onboarding NAP on $$nid (origin $(ORIGIN))"; \
	jb=$$(base64 < "$(JWT)" | tr -d '\n'); \
	sb=$$(base64 < onboard/nap-onboard.sh | tr -d '\n'); \
	cid=$$($(AWS) ssm send-command --instance-ids $$nid --document-name AWS-RunShellScript \
	  --comment "nap onboard" \
	  --parameters commands="[\"set -e\",\"echo $$jb | base64 -d > /tmp/nginx-license.jwt\",\"echo $$sb | base64 -d > /tmp/nap-onboard.sh\",\"chmod +x /tmp/nap-onboard.sh\",\"ORIGIN=$(ORIGIN) bash /tmp/nap-onboard.sh /tmp/nginx-license.jwt 2>&1 | tail -60\",\"rm -f /tmp/nginx-license.jwt\"]" \
	  --query 'Command.CommandId' --output text); \
	echo "command $$cid dispatched. tail the output with:"; \
	echo "  $(AWS) ssm get-command-invocation --command-id $$cid --instance-id $$nid --query StandardOutputContent --output text"

tunnel:
	@nid=$(NAP_ID); \
	echo "forwarding 127.0.0.1:$(SSH_LOCAL_PORT) -> $$nid:22"; \
	echo "then: export NGINX_SSH_HOST=127.0.0.1 NGINX_SSH_PORT=$(SSH_LOCAL_PORT) NGINX_SSH_USER=ubuntu NGINX_SSH_KEY=$$PWD/.secrets/vpcopilot_nap.pem"; \
	$(AWS) ssm start-session --target $$nid \
	  --document-name AWS-StartPortForwardingSession \
	  --parameters "portNumber=22,localPortNumber=$(SSH_LOCAL_PORT)"

ssh:
	@ssh -i .secrets/vpcopilot_nap.pem -p $(SSH_LOCAL_PORT) \
	  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@127.0.0.1

shell:
	@$(AWS) ssm start-session --target $(NAP_ID)

nap-status:
	@$(AWS) ec2 describe-instances --filters "$(TAGF)" \
	  --query 'Reservations[].Instances[].{ID:InstanceId,Name:Tags[?Key==`Name`]|[0].Value,State:State.Name,Type:InstanceType,IP:PublicIpAddress}' \
	  --output table

nap-down:
	@ids=$$($(AWS) ec2 describe-instances --filters "$(TAGF)" "Name=instance-state-name,Values=running,pending" \
	  --query 'Reservations[].Instances[].InstanceId' --output text); \
	if [ -z "$$ids" ]; then echo "no running $(PROJECT) box"; else \
	  echo "stopping (Project=$(PROJECT)): $$ids"; \
	  $(AWS) ec2 stop-instances --instance-ids $$ids \
	    --query 'StoppingInstances[].{id:InstanceId,state:CurrentState.Name}' --output table; fi

nap-up:
	@ids=$$($(AWS) ec2 describe-instances --filters "$(TAGF)" "Name=instance-state-name,Values=stopped,stopping" \
	  --query 'Reservations[].Instances[].InstanceId' --output text); \
	if [ -z "$$ids" ]; then echo "no stopped $(PROJECT) box"; else \
	  echo "starting: $$ids"; $(AWS) ec2 start-instances --instance-ids $$ids >/dev/null; \
	  $(AWS) ec2 wait instance-running --instance-ids $$ids; echo "running."; fi

nap-nuke:
	terraform destroy
