#!/usr/bin/python3
import asyncio
import aiohttp

iq_url = "http://localhost:8070"
iq_auth = aiohttp.BasicAuth("admin", "admin123")
filename = "iq_license_bom_report.csv"

licenseFilter = ["No-Source-License","Not-Supported","No-Sources", "Not-Declared"]
threatFilter = ["Sonatype Informational","Sonatype Special Licenses"]
headers = ["PublicId", "Stage", "ThreatGroup", "License", "Component"]
iq_session = ""

#------------------------------------------
async def main():
    global iq_session
    processed = [] 
    iq_session = aiohttp.ClientSession()
    apps = await get_applications()
    print(f"Checking {len(apps)} applications.")
    for app in apps:
        reports = await get_reports(app['id'])
        if reports is not None:
            for report in reports:
                print(f"Processing {app['publicId']}, {report['stage']}")
                components = await get_components(report['reportDataUrl'])
                if components is not None:
                    for component in components:
                        row = [ app['publicId'], report['stage'] ]+handle(component)
                        processed.append(row)

    await iq_session.close()
    if len(processed) > 0:
        processed.sort(key = lambda x: (x[0], x[1], x[2], x[4]))
        with open(filename,'w') as f:
            f.write(",".join(headers)+"\n")
            for data in processed:
                f.write(",".join(data)+"\n")
        print(f"Saved componets to {filename}")

#------------------------------------
async def get_url(url, root=""):
    resp = await iq_session.get(url, auth=iq_auth)
    return await handle_resp(resp, root)

async def handle_resp(resp, root=""):
    if resp.status != 200: print(await resp.text()); return None
    node = await resp.json()
    if root in node: node = node[root]
    if node is None or len(node) == 0: return None
    return node

async def get_applications():
    url = f"{iq_url}/api/v2/applications"
    return await get_url(url, "applications")

async def get_reports(appId):
    url = f"{iq_url}/api/v2/reports/applications/{appId}"
    return await get_url(url)

async def get_components(reportUrl):
    url = f"{iq_url}/{reportUrl}"
    return await get_url(url, "components")

def handle(component):
    purl, license, group = component['packageUrl'], "unknown", "unknown"
    if purl is None: 
        purl = f"{component['pathnames']}:{component['hash']}"
    else:
        dd, ls, gs, purl = component['licenseData'], [], [], str(purl.split("?")[0])
        for ll in dd['declaredLicenses']+dd['observedLicenses']:
            if ll['licenseId'] not in licenseFilter: 
                ls.append(ll['licenseId'])
        license = ":".join(sorted(set(ls)))
        for ll in dd['effectiveLicenseThreats']:
            if ll['licenseThreatGroupName'] not in threatFilter: 
                gs.append(ll['licenseThreatGroupName'])
        group = ":".join(sorted(set(gs)))
    return [group, license, purl]

#-----------------------------------------------------------------------------
if __name__ == "__main__":
    asyncio.run(main())
