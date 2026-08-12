# vpcopilot-lab — provision + COST CONTROL for the Advanced-WAF BIG-IP lab.
# Every stop/start is scoped to Project=$(PROJECT) so it can never touch another
# estate. Override on the command line, e.g.  make lab-down AWS_PROFILE=vpcopilot
#
#   make check         verify tooling + profile + subscription readiness
#   make plan/apply    stand the lab up (Terraform)
#   make lab-down      STOP the instances  (kills EC2 + PAYG hourly; keeps config)
#   make lab-up        START them again    (no re-onboarding needed)
#   make lab-status    show instance states
#   make tunnel        open the SSM port-forward to BIG-IP management
#   make origin-deploy build+run Larkspur on the origin over SSM
#   make origin-shell  SSM shell on the origin
#   make lab-nuke      terraform destroy (zero idle cost; re-onboard on next apply)

AWS_PROFILE ?= vpcopilot
REGION      ?= us-east-2
PROJECT     ?= vpcopilot-lab
APP_PORT    ?= 8080
MGMT_PORT   ?= 443
LOCAL_PORT  ?= 18443

AWS := aws --profile $(AWS_PROFILE) --region $(REGION)
TAGF := Name=tag:Project,Values=$(PROJECT)

.PHONY: check init plan apply lab-status lab-down lab-up tunnel origin-deploy origin-shell lab-nuke whoami keypair

check:
	@echo "profile : $(AWS_PROFILE)"; echo "region  : $(REGION)"
	@command -v terraform >/dev/null && echo "terraform: $$(terraform version | head -1)" || echo "terraform: MISSING"
	@command -v session-manager-plugin >/dev/null && echo "ssm-plugin: present" || echo "ssm-plugin: MISSING (brew install --cask session-manager-plugin)"
	@$(AWS) sts get-caller-identity --query 'Account' --output text >/dev/null 2>&1 \
	  && echo "identity : $$($(AWS) sts get-caller-identity --query 'Account' --output text)" \
	  || { echo "identity : profile '$(AWS_PROFILE)' not configured — run: aws configure --profile $(AWS_PROFILE)"; exit 1; }
	@echo -n "awaf ami : "; $(AWS) ec2 describe-images --owners 679593333241 \
	  --filters 'Name=name,Values=*Adv WAF*' --query 'length(Images)' --output text 2>/dev/null \
	  | awk '{if ($$1+0>0) print $$1" Advanced-WAF images visible (subscription OK)"; else print "0 — accept the AWAF Marketplace subscription first"}'

keypair:
	@test -f .secrets/vpcopilot_lab.pub && echo ".secrets/ keypair already present" || { \
	  mkdir -p .secrets && ssh-keygen -t rsa -b 4096 -N '' -f .secrets/vpcopilot_lab.pem \
	  && mv .secrets/vpcopilot_lab.pem.pub .secrets/vpcopilot_lab.pub && echo "generated .secrets/vpcopilot_lab.{pem,pub}"; }

init:
	terraform init

plan: keypair
	terraform plan

apply: keypair
	terraform apply

whoami:
	@$(AWS) sts get-caller-identity --output table

lab-status:
	@$(AWS) ec2 describe-instances --filters "$(TAGF)" \
	  --query 'Reservations[].Instances[].{ID:InstanceId,Name:Tags[?Key==`Name`]|[0].Value,State:State.Name,Type:InstanceType}' \
	  --output table

lab-down:
	@ids=$$($(AWS) ec2 describe-instances --filters "$(TAGF)" "Name=instance-state-name,Values=running,pending" \
	  --query 'Reservations[].Instances[].InstanceId' --output text); \
	if [ -z "$$ids" ]; then echo "no running $(PROJECT) instances"; else \
	  echo "stopping (Project=$(PROJECT)): $$ids"; \
	  $(AWS) ec2 stop-instances --instance-ids $$ids \
	    --query 'StoppingInstances[].{id:InstanceId,state:CurrentState.Name}' --output table; fi

lab-up:
	@ids=$$($(AWS) ec2 describe-instances --filters "$(TAGF)" "Name=instance-state-name,Values=stopped,stopping" \
	  --query 'Reservations[].Instances[].InstanceId' --output text); \
	if [ -z "$$ids" ]; then echo "no stopped $(PROJECT) instances"; else \
	  echo "starting: $$ids"; $(AWS) ec2 start-instances --instance-ids $$ids >/dev/null; \
	  $(AWS) ec2 wait instance-running --instance-ids $$ids; \
	  echo "running. open the mgmt tunnel with: make tunnel"; fi

# --- origin id / bigip mgmt ip resolved at run time (from tags / terraform state)
ORIGIN_ID = $$($(AWS) ec2 describe-instances --filters "$(TAGF)" "Name=tag:Role,Values=origin" \
	"Name=instance-state-name,Values=running" --query 'Reservations[0].Instances[0].InstanceId' --output text)

tunnel:
	@oid=$(ORIGIN_ID); mgmt=$$(terraform output -raw bigip_mgmt_private_ip); \
	echo "forwarding 127.0.0.1:$(LOCAL_PORT) -> $$mgmt:$(MGMT_PORT) via $$oid"; \
	echo "then: export BIGIP_URL=https://127.0.0.1:$(LOCAL_PORT)"; \
	$(AWS) ssm start-session --target $$oid \
	  --document-name AWS-StartPortForwardingSessionToRemoteHost \
	  --parameters "host=$$mgmt,portNumber=$(MGMT_PORT),localPortNumber=$(LOCAL_PORT)"

origin-shell:
	@$(AWS) ssm start-session --target $(ORIGIN_ID)

# Ship labs/larkspur-bank (two levels up) to the origin over SSM and run it. The
# tree is a handful of small files, well within the RunShellScript payload limit.
origin-deploy:
	@oid=$(ORIGIN_ID); \
	echo "packaging labs/larkspur-bank -> $$oid"; \
	tar czf /tmp/larkspur.tgz -C ../../labs larkspur-bank; \
	b64=$$(base64 < /tmp/larkspur.tgz | tr -d '\n'); \
	cid=$$($(AWS) ssm send-command --instance-ids $$oid --document-name AWS-RunShellScript \
	  --comment "deploy larkspur" \
	  --parameters commands="[\"set -e\",\"mkdir -p /opt/vpcopilot\",\"echo $$b64 | base64 -d > /tmp/larkspur.tgz\",\"tar xzf /tmp/larkspur.tgz -C /opt/vpcopilot\",\"cd /opt/vpcopilot/larkspur-bank\",\"docker build -t larkspur .\",\"docker rm -f larkspur 2>/dev/null || true\",\"docker run -d --restart unless-stopped --name larkspur -p $(APP_PORT):8080 larkspur\"]" \
	  --query 'Command.CommandId' --output text); \
	echo "command $$cid dispatched; tail with: $(AWS) ssm get-command-invocation --command-id $$cid --instance-id $$oid"

lab-nuke:
	terraform destroy
