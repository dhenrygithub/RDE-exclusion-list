#!/usr/bin/env python

""" iphandler.py: reporting matching IP addresses between the two files."""

import ipaddress 
from pprint import pprint
from tabulate import tabulate
import pandas

import csv
from copy import deepcopy
import logging
import os
import sys

IP_NETWORK_TYPE = type(ipaddress.ip_network('0.0.0.0/0'))
IP_ADDRESS_TYPE = type(ipaddress.ip_address('0.0.0.0'))
CANDIDATE_FILE = 'candidates-2021-ACAS-CRED.csv'
DATABASE_FILE = 'database.csv'
DATABASE_OUT_FILE = 'database_out.csv'


def toIPAddress(addrStr):
    if not isIPAddress(addrStr):
        return

    return ipaddress.ip_address(addrStr)


def toIPNetwork(addrStr):
    if not isIPNetwork(addrStr): return

    return ipaddress.ip_network(addrStr)


def isValidOctetValue(num):
    MIN = 0
    MAX = 255

    if all([c.isdigit() for c in num]):
        num = int(num)
        validOctetValue = (MIN <= num <= MAX)
    else:
        validOctetValue = False

    return validOctetValue


def isIPAddress(inputString):
    validOctetCount = 4

    octets = inputString.split(".")
    validIPAddress = False

    # are the elements that split both non-empty and a valid digit
    if ((all([o and isValidOctetValue(o) for o in octets]))
        and (len(octets) == validOctetCount)
        ):
        validIPAddress = True

    return validIPAddress


def isIPRange(inputString):
    validRangeItemCount = 2
    rangeSeparator = "-"
    # Separator must have a valid IP in front of it
    # x.x.x.x-[...]
    #        ^ pos = 7
    minimumRangeSeparatorPos = 7

    inputString = inputString.strip()

    validIPRange = False

    if (inputString.find(rangeSeparator) >= minimumRangeSeparatorPos):
        rangeItems = inputString.split(rangeSeparator)
    else:
        return False

    if ((len(rangeItems) == validRangeItemCount)
        and (all([isIPAddress(i) for i in rangeItems]))
        ):
        if (toIPAddress(rangeItems[0]) < toIPAddress(rangeItems[1])):
            validIPRange = True
    else:
        return False

    return validIPRange


def isIPNetwork(inputString):
    MAX_CIDR = 32
    MIN_CIDR = 0
    validNetworkItemCount = 2
    validIPNetwork = False

    inputString = inputString.strip()

    if (inputString.find("/") > 0):
        networkItems = inputString.split("/")
    else:
        return False

    networkIP = networkItems[0]

    if (networkItems[1].isdigit()):
        networkCIDR = int(networkItems[1])
    else:
        return False

    if ( (len(networkItems) == validNetworkItemCount)
        and (isIPAddress(networkIP))
        and (MIN_CIDR <= networkCIDR <= MAX_CIDR)
    ):
        validIPNetwork = True

    return validIPNetwork


def isSingleDatum(inputString):

    items = reduceDatum(inputString)

    return len(items) == 1


def invalidDatum(entry, reason):
    entry['valid'] = False
    entry['reason_invalid'] = reason
    return entry


def reduceDatum(inputString):
    # a datum is defined as anything in a string that is separated by commas,
    # excluding blanks and nulls.
    # Example:
    # - blanks "  , ,    ,  ,   "
    # - nulls/missing values ",,,"

    # remove leading, trailing blanks
    inputString = inputString.strip()
    # split across commas
    items = inputString.split(",")
    # remove null items and whitespace in case of leading, trailing or repeated commas
    items = [x.strip() for x in items if x.strip()]

    return items


def processSingleDatum(entry):

    if isIPAddress(entry['string']):
        entry['valid'] = True
        entry['IP'] = toIPAddress(entry['string'])
        entry['IPtype'] = "IPAddress"
        entry['host_count'] = 1
    elif isIPRange(entry['string']):
        entry['valid'] = True
        entry['IPStart'] = toIPAddress(entry['string'].split("-")[0])
        entry['IPEnd'] = toIPAddress(entry['string'].split("-")[1])
        entry['IPtype'] = "IPRange"
        entry['host_count'] = (int(entry['IPEnd']) - int(entry['IPStart']) + 1)
    elif isIPNetwork(entry['string']):
        entry['valid'] = True
        entry['IPtype'] = "IPNetwork"
        entry['IPNetwork'] = toIPNetwork(entry['string'])
        entry['host_count'] = (toIPNetwork(entry['string']).num_addresses - 2) # Exclude broadcast and network addresses
    else: entry = invalidDatum(entry, "not an IP, range, or network")

    return entry


def readDatabase():
    """"
    # extract IP addresses from the input database list of dicts
    addrList = [ sub['string'] for sub in db ]

    # test data
    addrList = [
        "10.200.7.3-10.200.7.4,10.200.10.101-10.200.10.104,10.200.23.3-10.200.23.4,10.200.24.3-10.200.24.4,134.164.7.3-134.164.7.4,134.164.7.23,134.164.7.25,134.164.23.3-134.164.23.4,134.164.23.16/30,134.164.23.21-134.164.23.23,134.164.23.29,134.164.23.32,134.164.23.34-134.164.23.38,134.164.23.41-134.164.23.42,134.164.23.45,134.164.23.49-134.164.23.50,134.164.23.58-134.164.23.60,134.164.23.62,134.164.23.64,134.164.23.68/31,134.164.23.73,134.164.23.76,134.164.23.78,134.164.23.80,134.164.23.84,134.164.23.88,134.164.23.90,134.164.23.95-134.164.23.96,134.164.23.98/31,134.164.23.104,134.164.23.113-134.164.23.116,134.164.23.118,134.164.23.121,134.164.23.123,134.164.23.125-134.164.23.133,134.164.23.136-134.164.23.141,134.164.23.143-134.164.23.152,134.164.23.156-134.164.23.162,134.164.23.166-134.164.23.174,134.164.23.176,134.164.23.178,134.164.23.180,134.164.23.182,134.164.23.185,134.164.23.188,134.164.23.191-134.164.23.193,134.164.23.195,134.164.23.197-134.164.23.199,134.164.23.202,134.164.23.204-134.164.23.209,134.164.23.212,134.164.23.218/31,134.164.23.221-134.164.23.223,134.164.23.225,134.164.23.227-134.164.23.230,134.164.23.234-134.164.23.249,134.164.24.3-134.164.24.4,134.164.24.11-134.164.24.19,134.164.24.21-134.164.24.25,134.164.24.27,134.164.24.31,134.164.24.34,134.164.24.38,134.164.24.40-134.164.24.45,134.164.24.50,134.164.24.53-134.164.24.57,134.164.24.60/31,134.164.24.63,134.164.24.65,134.164.24.67-134.164.24.74,134.164.24.78,134.164.24.85,134.164.24.94,134.164.24.97-134.164.24.98,134.164.24.102,134.164.24.110/31,134.164.24.115,134.164.24.120-134.164.24.124,134.164.24.127-134.164.24.134,134.164.24.141,134.164.24.143-134.164.24.144,134.164.24.147,134.164.24.150-134.164.24.152,134.164.24.154,134.164.24.156,134.164.24.160,134.164.24.165,134.164.24.167-134.164.24.178,134.164.24.181-134.164.24.183,134.164.24.185-134.164.24.188,134.164.24.190-134.164.24.194,134.164.24.196/31,134.164.24.200/30,134.164.24.220-134.164.24.238,134.164.24.241,192.168.190.250",
        "10.1.1.1,10.1.1.2 , 10.1.1.11, 10.1.1.91", "199.123.89.81",
        "256.666.1.0/24",
        "255.66.1.0/24",
        "0.0.0.0", "0.0.0.0-0.0.0.1", "0.0.0.0/24",
        "192.168.0.1",
        "255", "256", "0", "1", "-1", "10.", "9.6",
        "/", "*", "."
    ]
    """""

    db = []
    expanded_db = []

    # 1) read items
    with open(DATABASE_FILE, 'r') as database_file:

        data = csv.reader(database_file, delimiter=',')
        line_count = 0
        for row in data:
            line_count += 1
            entry={
                'num': line_count,
                'group': row[0],
                'string': row[1],
                'host_count': 0,
                'valid': False
            }
            db.append(entry)

    print(tabulate(db, tablefmt='psql'))

    for db_entry in db:
        # Collapse blanks and commas
        addr = db_entry['string']
        db_entry['string'] = ",".join(reduceDatum(addr))

        # 1.1) is it single or multiple?
        if isSingleDatum(db_entry['string']):
            # 1.1.2) SING
            expanded_db.append(processSingleDatum(db_entry))
        else:
            # 1.1.1) MULT iterate over and do SING process
            for datum in db_entry['string'].split(","):
                expanded_entry = deepcopy(db_entry)
                expanded_entry['string'] = datum
                #datum = reduceDatum(datum)
                expanded_db.append(processSingleDatum(expanded_entry))

    # TODO: 2) remove duplicates
    print('\nNumber of lines in database file:', line_count)
    print("Number of expanded database entries:", len(expanded_db))
    print("Number of hosts in expanded database:", sum(entry['host_count'] for entry in expanded_db), '\n')
    pprint(expanded_db)
    print('\n')

    return expanded_db


def readCandidates_pandas():

    """
    cand = []
    addr1 = toIPAddress('134.164.7.23')
    addr2 = toIPAddress('10.1.1.91')
    cand.append({"IP": addr1,
                 "IPtype": "IPAddress"
                 })
    cand.append({"IP": addr2,
                 "IPtype": "IPAddress"
                 })
    return (cand)
    """
    candidates = []

    candidates_df = pandas.read_csv(CANDIDATE_FILE)
    # candidates = candidates_df['IP'].values.tolist()

    print(tabulate(candidates_df))

    total_records = candidates_df.groupby(['site']).count()

    print("\nTotal records read by site:\n", candidates_df['site'].value_counts())

    print("\nTotal records:\n", candidates_df['site'].value_counts().sum())

    for index, row in candidates_df.iterrows() :
        candidates.append({"IP": toIPAddress(row['IP']),
                     "IPtype": "IPAddress"
                     })

    return candidates


def readCandidates_csv():

    candidates = []

    with open(CANDIDATE_FILE, 'r') as candidate_file:
        print('\n[[ Reading Candidates File ]]\n')

        data = csv.DictReader(candidate_file, delimiter=',')
        line_count = 0
        candidate_duplicates = 0

        for row in data:
            line_count += 1
            candidate = {
                'num': line_count,
                'site': row['Repository'],
                'IPtype': 'IPAddress',
                'string': row['IP Address'],
                'IP': toIPAddress(row['IP Address']),
                'DNS': row['DNS Name'],
                'NetBIOS': row['NetBIOS Name'],
                'host_count': 1,
                'valid': True
            }

            # insert candidate into list if not already in the list, and count duplicates if found
            if not [existing for existing in candidates if existing['IP'] == candidate['IP']]:
                candidates.append(candidate)
            else:
                candidate_duplicates += 1

    print('\nNumber of lines in candidates file :', line_count)
    print("Number of hosts in candidates:", sum(entry['host_count'] for entry in candidates))
    print("Number of duplicate candidates:", candidate_duplicates, '\n')
#    print(tabulate(candidates, tablefmt='psql'))

#    total_records = candidates_df.groupby(['site']).count()

#    print("\nTotal records read by site:\n", candidates_df['site'].value_counts())

#    print("\nTotal records:\n", candidates_df['site'].value_counts().sum())

    return candidates


def lookForCandidatesInDatabase(listCand, listData):
    match_count = 0
    for cand in listCand:
        if cand['valid']:
            for data in listData:
                if data['valid']:
                    if data['IPtype'] == 'IPAddress':
                        if cand['IP'] == data['IP']:
                            print(data['group'], "found at site:", cand['site'], ":", cand['IP'], "matched excluded IP", data['IP'])
                            match_count += 1
                    elif data['IPtype'] == 'IPNetwork':
                        if cand['IP'] in data['IPNetwork']:
                            print(data['group'], "found at site:", cand['site'], ":", cand['IP'], "in excluded network", data['IPNetwork'])
                            match_count += 1
                    else:
                        if data['IPStart'] <= cand['IP'] <= data['IPEnd']:
                            print(data['group'], "found at site:", cand['site'], ":", cand['IP'], "in excluded IP range", data['string'])
                            match_count += 1
    print("\n", match_count, "matches found.")

def writeDatabase_csv(listData):
    with open(DATABASE_OUT_FILE, 'w', newline='') as database_out_file:
        # Open CSV
        #analyze_output_file = open(output_name, mode='a')
        # create the csv writer object
        database_out_writer = csv.writer(database_out_file, delimiter=',', quotechar='"',
                                        quoting=csv.QUOTE_MINIMAL)
        # Write Header Rows
        database_out_writer.writerow(["IP Address",
                            "Host Name/DNS",
                            "Device Type/Model",
                            "Operating System",
                            "Reason for Exclusion",
                            "Repository",
                            "Confirmed",
                            "Entry Type",
                            "Original Se#"
                            ])
					

        for entry in listData:
            # create the csv writer object
            if entry['IPtype'] == 'IPAddress':
                database_out_writer.writerow(
                    [entry['IP'], '', entry['group'], '', entry['group'], '', '', f"Single IP Address", entry['num']])
            elif entry['IPtype'] == 'IPNetwork':
                for dataIP in entry['IPNetwork']:
                    database_out_writer.writerow(
                        [dataIP, '', entry['group'], '', entry['group'], '', '', f"IP Network {entry['string']}", entry['num']])
            else: # IP range
                for dataIP in range(int(entry['IPStart']), int(entry['IPEnd'])):
                    database_out_writer.writerow(
                        [dataIP, '', entry['group'], '', entry['group'], '', '', f"IP Range {entry['string']}", entry['num']])

        database_out_file.close()

if __name__ == '__main__':  # pragma: nocover
    candidates = readCandidates_csv()
    database = readDatabase()
    lookForCandidatesInDatabase(candidates, database)
    writeDatabase_csv(database)
