import boto3
import requests
import json
import time
import os

# suppressing insecure tls warning to make output look cleaner
requests.packages.urllib3.disable_warnings()

# Enviroment variable for all stuffs
INSIGHTVMBASEURL = os.environ.get('INSIGHTVMBASEURL')
insightcreds = os.environ.get('INSIGHTVM_CREDS')
INSIGHTREPORTID = os.environ.get('INSIGHTREPORTID')
AWSAMIID = os.environ.get('AWSAMIID')
AWSKEYPAIR = os.environ.get('AWSKEYPAIR')
AWSAVAILABILITYZONE = os.environ.get('AWSAVAILABILITYZONE')
AWSSUBNETID = os.environ.get('AWSSUBNETID')

INSIGHTTEMPLATEID = os.environ.get('INSIGHTTemplate')

def ec2launch():
    print("Launching Instance")
    ec2 = boto3.resource('ec2')
    instances = ec2.create_instances(
        ImageId= AWSAMIID,
        MinCount=1,
        MaxCount=1,
        Placement={
            'AvailabilityZone': AWSAVAILABILITYZONE
        },
        SubnetId=AWSSUBNETID,
        InstanceType='t2.micro',
        KeyName= AWSKEYPAIR,
    #    PrivateIpAddress='172.31.80.20',
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {
                        'Key': 'Name',
                        'Value': 'Testing-Server'
                    },
                ]
            },
        ]
    )
    instanceid= instances[0].instance_id
    return instanceid # To spit this into the describe instances thingy

#getting instance IP
def ec2ip(instanceid):
    print("Printing Instance IPv4 address")
    desec2 = boto3.client('ec2')
    response = desec2.describe_instances(
        InstanceIds=[instanceid,]
    )
    ipaddress = response['Reservations'][0]['Instances'][0]['PrivateIpAddress']
    return(ipaddress)

# Getting Instance Status
def instancestatus(instanceid):
    desec2 = boto3.client('ec2')
    response = desec2.describe_instances(
        Filters=[
        ],
        InstanceIds=[
            instanceid,
        ],
    )
    instatus = response['Reservations'][0]['Instances'][0]['State']['Name']
    #  The valid values are 0 (pending), 16 (running), 32 (shutting-down), 48 (terminated), 64 (stopping), and 80 (stopped).
    return instatus


# Starting Scan for InsightVM
def insightvmscan(ipaddress): #i need to make 192.168.10.100 a variable.
    url = INSIGHTVMBASEURL + 'api/3/sites/4/scans'
    jsonpayload = {
        "engineId": "",
        "hosts": [
            ipaddress
        ],
        "name": "",
        "templateId": INSIGHTTEMPLATEID
    }

    payload = json.dumps(jsonpayload)
    headers = {
        'Accept': "application/json;charset=UTF-8",
        'Content-Type': "application/json",
        'cache-control': "no-cache",
        'Authorization': insightcreds
    }
    response = requests.request("POST", url, data=payload, headers=headers, verify=False)
    # Doing some error handling cleanuo
    statuscode = (response.status_code)
    if statuscode is '200' or '201':
        print("InsightVM Scan = Starting")
    else:
        print("Failed on InsightVM Scan - Now Terminating AWS Instance")
        cleanup(insidvar)
        exit(1)
    json_par = json.loads(response.text)
    rawscanid = (json_par['links'][1]['id'])
    scanid = str(rawscanid)
    return scanid


# Checking InsightVM Scan Status
def insightscanstatus(scanid):
    url = INSIGHTVMBASEURL + "api/3/scans/" + scanid

    headers = {
        'Accept': "application/json;charset=UTF-8",
        'Content-Type': "application/json",
        'Authorization': insightcreds,
        'Cache-Control': "no-cache",
        'Host': INSIGHTVMBASEURL,
    }
    response = requests.request("GET", url, headers=headers, verify=False)
    # Doing some error handling cleanuo
    statuscode = (response.status_code)
    if statuscode is '200' or '201':
        print("InsightVM Scan = Running")
    else:
        print("Failed on InsightVM Scan Status - Now Terminating AWS Instance")
        cleanup(insidvar)
        exit(1)
    print("InsightVM Scan = Complete")
    scaninfo = json.loads(response.text)
    scanstatus = (scaninfo['status'])
    return scanstatus

def updateinsightvmreport(scanid):
    url = INSIGHTVMBASEURL + "api/3/reports/" + INSIGHTREPORTID
    scanid = "213798"
    payload = "{\n\t\n\t\"name\": \"Single Asset Report\",\n\t\"format\": \"sql-query\",\n\t\"query\": \"SELECT CAST('summary' as text) as resulttype, cast('vulnerabilities' as text) as title, cast('' as text) as issue, CAST(fa.vulnerabilities as DECIMAL(10,1)) as score, CAST('' as text) as details FROM dim_asset da\\nleft join fact_asset fa on da.asset_id = fa.asset_id\\nUNION ALL\\nSELECT CAST('summary' as text) as resulttype, cast('credentials' as text) as title, cast('' as text) as issue, dacs.aggregated_credential_status_id as score, dacs.aggregated_credential_status_description as details FROM dim_asset da\\nleft join fact_asset fa on da.asset_id = fa.asset_id\\nleft join dim_aggregated_credential_status dacs ON fa.aggregated_credential_status_id = dacs.aggregated_credential_status_id\\nUNION ALL\\nSELECT CAST('summary' as text) as resulttype, cast('critical' as text) as title, cast('' as text) as issue, fa.critical_vulnerabilities as score, CAST('' as text) as details FROM dim_asset da\\nleft join fact_asset fa on da.asset_id = fa.asset_id\\nUNION ALL\\nSELECT CAST('summary' as text) as resulttype, cast('severe' as text) as title, cast('' as text) as issue, fa.severe_vulnerabilities as score, CAST('' as text) as details FROM dim_asset da\\nleft join fact_asset fa on da.asset_id = fa.asset_id\\nUNION ALL\\nSELECT CAST('summary' as text) as resulttype, cast('moderate' as text) as title, cast('' as text) as issue, fa.moderate_vulnerabilities as score, CAST('' as text) as details FROM dim_asset da\\nleft join fact_asset fa on da.asset_id = fa.asset_id\\nUNION ALL\\nSELECT CAST('summary' as text) as resulttype, cast('risk' as text) as title, cast('' as text) as issue, CAST(fa.riskscore as DECIMAL(10,1)) as score, CAST('' as text) as details FROM dim_asset da\\nleft join fact_asset fa on da.asset_id = fa.asset_id\\nUNION ALL\\nSELECT cast('vuln' as text) as resulttype, cast('finding' as text) as title, dv.title AS issue, CAST(dv.cvss_score as decimal(10,1)) as score, favf.proof as details FROM fact_asset_vulnerability_instance AS favf\\nLEFT JOIN dim_asset AS da on favf.asset_id = da.asset_id\\nLEFT JOIN dim_vulnerability as dv on favf.vulnerability_id = dv.vulnerability_id\\nUNION ALL\\nselect cast('policy' as text), dp.title AS title, dpr.title AS issue, 0, faprc.proof AS proof FROM fact_asset_policy_rule_check faprc\\nleft join dim_policy_rule dpr ON dpr.rule_id = faprc.rule_id\\nleft join dim_policy dp ON dp.policy_id = faprc.policy_id\\nwhere faprc.compliance = false\",\n\t\"scope\": {\n\t\t\"assets\": [\n\t\t\t\n\t\t],\n\t\t\"scan\":" + scanid + "\n\t},\n\t\"version\": \"2.3.0\"\n}"

    headers = {
        'Accept': "application/json;charset=UTF-8",
        'Content-Type': "application/json",
        'Authorization': insightcreds,
        'Cache-Control': "no-cache",
        'Host': INSIGHTVMBASEURL,
    }
    # Doing some error handling cleanuo
    response = requests.request("PUT", url, data=payload, headers=headers, verify=False)
    # Doing some error handling cleanuo
    statuscode = (response.status_code)
    if statuscode is '200' or '201':
        print("Updating Scan Report to scan current instance")
    else:
        print("Failed on updating scan report - Now Terminating AWS Instance")
        cleanup(insidvar)
        exit(1)
    print(response.text)

def GetScanReportInstance():

    url = INSIGHTVMBASEURL + "api/3/reports/" + INSIGHTREPORTID + "/generate"

    headers = {
        'Accept': "application/json;charset=UTF-8",
        'Content-Type': "application/json",
        'Authorization': insightcreds,
        'Cache-Control': "no-cache",
        'Host': INSIGHTVMBASEURL,
        }

    response = requests.request("POST", url, headers=headers, verify=False)

    statuscode = (response.status_code)
    if statuscode is '200' or '201':
        print("Getting Scan Report")
    else:
        print("Failed on getting scan report - Now Terminating AWS Instance")
        cleanup(insidvar)
        exit(1)

    JsonResponse = json.loads(response.text)
    RepInstID = (JsonResponse['id'])
    ScanReportInstance = str(RepInstID)
    return(ScanReportInstance)

def ReportGenerateStatus(ScanReportInstance):
    url = INSIGHTVMBASEURL + "api/3/reports/" + INSIGHTREPORTID +"/history/" + ScanReportInstance

    headers = {
        'Accept': "application/json;charset=UTF-8",
        'Content-Type': "application/json",
        'Authorization': insightcreds,
        'Cache-Control': "no-cache",
        'Host': INSIGHTVMBASEURL,
    }

    response = requests.request("GET", url, headers=headers, verify=False)
    statuscode = (response.status_code)
    if statuscode is '200' or '201':
        print("Getting Scan Report ID")
    else:
        print("Failed on getting scan report id - Now Terminating AWS Instance")
        cleanup(insidvar)
        exit(1)

    reportstatus = json.loads(response.text)
    ReportGenerationStatus = reportstatus['status']
    return ReportGenerationStatus


def DownloadReport(ScanReportInstance):
    url = INSIGHTVMBASEURL + "api/3/reports/"+ INSIGHTREPORTID +"/history/" + ScanReportInstance + "/output"

    headers = {
        'Accept': "application/octet-stream, application/json;charset=UTF-8",
        'Content-Type': "application/json",
        'Authorization': insightcreds,
        'Cache-Control': "no-cache",
        'Host': INSIGHTVMBASEURL,
        }

    response = requests.request("GET", url, headers=headers, verify=False)
    statuscode = (response.status_code)
    if statuscode is '200' or '201':
        print("Downloading Scan Report")
    else:
        print("Failed on downloading scan report - Now Terminating AWS Instance")
        cleanup(insidvar)
        exit(1)
    print(response.text)

# Terminate Instance and Cleanup what you just did
def cleanup(instanceid):
    print ('Killing instance')
    ec2 = boto3.resource('ec2')
    ids = [instanceid]
    print(instanceid)
    # ec2.instances.filter(InstanceIds=ids).stop()
    ec2.instances.filter(InstanceIds=ids).terminate()

insidvar = ec2launch()

status = "whatever"
while status != 'running':
    status = instancestatus(insidvar)
    print('Instance Launch Status = ' + status)
    if status == 'running':
        print('Instance is now Active')
        break
    time.sleep(5)


ipaddvar = ec2ip(insidvar)
print(ipaddvar)
ipaddvar = '192.168.10.100'

print("Running InsightVM Scan")
isid = insightvmscan(ipaddvar)

while status != 'finished':
    currentstatus = insightscanstatus(isid)
    if currentstatus == 'finished':
        print('Scan Complete')
        break
    time.sleep(5)
updateinsightvmreport(isid)


ReportInstanceID = GetScanReportInstance()
print("Generating Scan Report")

status = 'whatever'
while status != 'finished':
    currentstatus = ReportGenerateStatus(ReportInstanceID)
    if currentstatus == 'complete':
        print('Report Has been Generated Successfully')
        break
    time.sleep(5)

FinalReport = DownloadReport(ReportInstanceID)
print(FinalReport)

print("Now Killing Instance")
cleanup(insidvar)

