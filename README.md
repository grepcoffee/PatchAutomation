# AWS AMI Patching Automation 

Utlizies InsightVM, Packer, and Ansible for AWS image creation and automation of patches

** Please note I am still updating the documentation ** 

# Required Variables

1. INSIGHTVMBASEURL
   Rapid7 InsightVM Baseurl 
2. insightcreds 
   Rapid7 InsightVM Credentials (https://help.rapid7.com/insightvm/en-us/api/index.html#section/Overview/Authentication)
3. INSIGHTREPORTID 
   Scan Report ID (https://help.rapid7.com/insightvm/en-us/api/index.html#operation/getReportTemplates)
4. AWSAMIID 
   Base AMI you'd like to use (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/finding-an-ami.html#finding-an-ami-aws-cli)
5. AWSKEYPAIR 
   AWS Access Keys (https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html)
6. AWSAVAILABILITYZONE 
   Default Availability Zone you'd like to use (https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.RegionsAndAvailabilityZones.html)
7. AWSSUBNETID 
   Default Subnet utlized by company. (https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html)
