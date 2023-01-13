""" Copyright (c) 2020 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at
           https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

# Import Section
import os
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json

from rich.console import Console
from rich.progress import Progress
from rich.panel import Panel
from config import *

console = Console()

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

PLATFORM_URL = "https://" + HOSTNAME + "/api/fmc_platform/v1"
CONFIG_URL = "https://" + HOSTNAME + "/api/fmc_config/v1"


class FirePower:
    def __init__(self):
        """
        Initialize the FirePower class, log in to FMC,
        and save authentication headers
        """
        with requests.Session() as self.s:
            console.print(f"Attempting login to {HOSTNAME}")
            self.authRequest()

            self.headers = {
                "Content-Type": "application/json",
                "X-auth-access-token": self.token,
            }

    def authRequest(self):
        """
        Authenticate to FMC and retrieve auth token
        """
        authurl = f"{PLATFORM_URL}/auth/generatetoken"
        resp = self.s.post(authurl, auth=(USERNAME, PASSWORD), verify=False)
        if resp.status_code == 204:
            # API token, Refresh token, default domain, and
            # other info returned in HTTP headers
            console.print("[green][bold]Connected to FMC.")
            # Save auth token & global domain UUID
            self.token = resp.headers["X-auth-access-token"]
            self.global_UUID = resp.headers["DOMAIN_UUID"]
            console.print(f"\nGlobal domain UUID: {self.global_UUID}")
            return
        else:
            console.print("[red]Authentication Failed.")
            console.print(resp.text)
            sys.exit(1)

    def getNetworkGroup(self, group_name):
        """
        Get network group, if it exists
        """
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/networkgroups?limit=1000"
        resp = self.getData(url)

        if resp:
            resp_json = json.loads(resp)

            # If values are returned, find the matching element
            if 'items' in resp_json:
                for item in resp_json['items']:
                    if item['name'] == group_name:
                        return item

                return None

        else:
            console.print(f"[red]Could not find network group[/]: {group_name}")
            sys.exit(1)

    def createNetworkGroup(self, group_name, network_objects, network_literals):
        """
        Update existing network group if it exists, or create a new one
        """
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/networkgroups"

        group = self.getNetworkGroup(group_name)

        if group:
            # group found, overwrite literals and objects only
            data = {
                'name': group['name'],
                'id': group['id'],
                'objects': network_objects,
                'literals': network_literals
            }

            resp = self.putData(url + f"/{data['id']}", data)
        else:
            # create new group
            data = {
                'name': group_name,
                'description': 'Created from Country IP Blocklist',
                "overridable": False,
                'objects': network_objects,
                "literals": network_literals
            }

            resp = self.postData(url, data)

        return resp

    def getExtendedACL(self, acl_name):
        """
        Get extended acl, if it exists
        """
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/extendedaccesslists?limit=1000&expanded=true"
        resp = self.getData(url)

        if resp:
            resp_json = json.loads(resp)

            # If values are returned, find the matching element
            if 'items' in resp_json:
                for item in resp_json['items']:
                    if item['name'] == acl_name:
                        return item

                return None

    def createExtendedACL(self, acl_name, network_groups):
        """
        Update existing network group if it exists, or create a new one
        """
        url = f"{CONFIG_URL}/domain/{self.global_UUID}/object/extendedaccesslists"

        acl = self.getExtendedACL(acl_name)

        if acl:
            # acl found, add new entry if not already present
            data = {
                'name': acl['name'],
                'id': acl['id'],
                "entries": acl['entries']
            }

            # iterate through entries, check if network group entry already present, complete processing if matching
            # entry found
            for entry in data['entries']:
                id = entry['sourceNetworks']['objects'][0]['id']

                if id == network_groups[0]['id']:
                    return True

            #  add new entry
            data["entries"].append(
                {
                    "action": "DENY",
                    "logging": "DEFAULT",
                    "logInterval": 300,
                    "logLevel": "INFORMATIONAL",
                    "sourceNetworks": {
                        "objects": network_groups
                    }
                }
            )

            resp = self.putData(url + f"/{data['id']}", data)
        else:
            # create new extended acl
            data = {
                'name': acl_name,
                "entries": [
                    {
                        "action": "DENY",
                        "logging": "DEFAULT",
                        "logInterval": 300,
                        "logLevel": "INFORMATIONAL",
                        "sourceNetworks": {
                            "objects": network_groups
                        }
                    }
                ]
            }

            resp = self.postData(url, data)

        return resp

    def getData(self, get_url):
        """
        General function for HTTP GET requests with authentication headers
        """
        # console.print(f"Sending GET to: {get_url}")
        resp = self.s.get(get_url, headers=self.headers, verify=False)
        if resp.status_code == 200:
            return resp.text
        if resp.status_code == 404:
            return None
        else:
            console.print("[red]Request FAILED. " + str(resp.status_code))
            console.print("\nError from FMC:")
            console.print(resp.text)

    def putData(self, put_url, put_data):
        """
        General function for HTTP POST requests with authentication headers & some data payload
        """
        # console.print(f"Sending PUT to: {put_url}")
        resp = self.s.put(put_url, headers=self.headers, json=put_data, verify=False)
        # 200 returned for some successful object creations
        if resp.status_code == 200:
            return resp.text
        # 201 returned for most successful object creations
        if resp.status_code == 201:
            return resp.text
        # 202 is returned for accepted request
        if resp.status_code == 202:
            return resp.text
        else:
            console.print("[red]Request FAILED.[/] " + str(resp.status_code))
            console.print("\nError from FMC:")
            console.print(resp.text)
            console.print(put_data)

    def postData(self, post_url, post_data):
        """
        General function for HTTP POST requests with authentication headers & some data payload
        """
        # console.print(f"Sending PUT to: {post_url}")
        resp = self.s.post(post_url, headers=self.headers, json=post_data, verify=False)
        # 201 returned for most successful object creations
        if resp.status_code == 201:
            return resp.text
        # 202 is returned for accepted request
        if resp.status_code == 202:
            return resp.text
        else:
            console.print("[red]Request FAILED. " + str(resp.status_code))
            console.print("\nError from FMC:")
            console.print(resp.text)


def subnetMaskToCidr(subnet_mask):
    """
    Convert subnet mask to cidr notation
    """
    subnet_mask = subnet_mask.split('.')

    # Convert subnet mask to binary
    subnet_mask_binary = ''
    for octet in subnet_mask:
        subnet_mask_binary += f'{int(octet):08b}'

    # Return count of 1's
    return '/' + str(subnet_mask_binary.count('1'))


def processBlockList(fmc, file_name, country_name):
    """
    Create network group(s) from block list file. Note: 1000 network literals max per network group object (FMC 7.2.2 -
    limitation). Additional groups generated accordingly.
    """

    # Open ip block list file
    with open(file_name, 'r') as fp:

        # Get total number of networks (= number of lines)
        network_count = sum(1 for _ in fp)
        fp.seek(0)

        network_groups = []

        with Progress() as progress:
            overall_progress = progress.add_task("Overall Progress", total=network_count, transient=True)
            counter = 1
            group_number = 1

            # Iterate through network list
            network_literals = []
            for network in fp:
                # Isolate the parts of each line, remove trailing newline
                network = network.strip().split(' ')

                # Add each new network object
                network_literals.append({
                    "type": "Network",
                    'value': network[1] + subnetMaskToCidr(network[2]),
                })

                progress.console.print(
                    "Processing: [green]{}[/] ({} of {})".format(network[1], str(counter), network_count))

                # Create network group per 1000 literals, or last group
                if len(network_literals) == 1000 or counter == network_count:
                    # Network Group Name
                    sub_group_name = country_name + '-block-list-' + str(group_number)

                    # Create/update network group from literals list
                    resp = fmc.createNetworkGroup(sub_group_name, network_objects=[], network_literals=network_literals)

                    # Add each new network object
                    network_groups.append({"type": "NetworkGroup", "id": json.loads(resp)['id']})

                    if resp:
                        progress.console.print("Network Group Created: [green]{}[/]".format(sub_group_name))
                    else:
                        progress.console.print("[red]Failed to create network group {}, exiting...[/]".format(sub_group_name))
                        sys.exit(-1)

                    network_literals.clear()
                    group_number += 1

                counter += 1
                progress.update(overall_progress, advance=1)

        # Create/update larger group of network groups
        group_name = country_name + '-block-list'
        resp = fmc.createNetworkGroup(group_name, network_objects=network_groups, network_literals=[])

        console.print("All Network Group(s) Created!")

    # Return count of groups created
    return group_name


def generateAcl(fmc, group_name, acl_name):
    """
    Create or update country block list extended acl based on network object(s)
    """

    # Get network group
    net_group = fmc.getNetworkGroup(group_name)

    if net_group:
        console.print("Found: [green]{}[/]".format(net_group['name']))
    else:
        console.print("[red]Error, network group not found... skipping: {}[/]".format(group_name))

    # Create/update acl from network groups list
    resp = fmc.createExtendedACL(acl_name, [{"id": net_group["id"]}])

    if resp:
        console.print("Network group added to extended acl: [blue]{}[/]".format(acl_name))
    else:
        console.print("[red]Failed to create acl {}, exiting...[/]".format(acl_name))
        sys.exit(-1)

    return


def main():
    console.print(Panel.fit("FMC ACL Generation Tool ('countryipblocks.com')"))
    console.print('To use this tool, please enter the [yellow]File name[/] of the *.txt file containing the ['
                  'yellow]Network Object List[/] ([bold]Note:[/] ensure the file is in the current directory!), '
                  'then enter the [blue]Country Name[/]')

    # Enter Filename (must be in current directory)
    file_name = console.input('[yellow]File Name:[/] ')

    # Check current directory for file
    if not os.path.exists(file_name):
        console.print('[red]Error:[/] file not found!')
        sys.exit(-1)

    # Enter Country Name
    country_name = console.input('[blue]Country Name:[/] ')

    # Define FMC Class Object
    fmc = FirePower()

    # Create network group(s) from block list file
    console.print(Panel.fit("Create/Update Network Group(s)", title="Step 1"))
    group_name = processBlockList(fmc, file_name, country_name)

    # Generate and/or update extended ACL List
    console.print(Panel.fit("Create/Update Extended ACL(s)", title="Step 2"))

    # Enter Country ACL Name (if it exists, it will be modified, otherwise created)
    acl_name = console.input('[green]Extended ACL Name:[/] ')
    generateAcl(fmc, group_name, acl_name)

    return


if __name__ == "__main__":
    main()
