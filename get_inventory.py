import sys
from typing import Union, Dict
import csv
from argparse import ArgumentParser
from getpass import getpass
from pysnmp.hlapi import SnmpEngine, UdpTransportTarget,\
    ContextData, ObjectType, ObjectIdentity, bulkCmd
from pysnmp.hlapi import CommunityData, UsmUserData, usmNoAuthProtocol, usmNoPrivProtocol
from pysnmp.smi import builder, view, compiler


MIB_FILE_SOURCE = 'file://./mib/'


class InvalidSnmpVersion(Exception):
    """Invalide SNMP Version exception class"""
    pass


def get_args():
    """Obtain arguments from user input"""
    parser = ArgumentParser(
        usage='%(prog)s...',
        description='''SNMP Hardware Inventory.

This script is used to query a list of devices for their entPhysicalTable. The results are used to generate a CSV report detailing the hardware components for each device.'''
    )

    parser.add_argument(
        '-i',
        metavar='inventory',
        type=str,
        required=True,
        help='An inventory text file containing an IP or FQDN per line.'
    )
    parser.add_argument(
        '-m',
        metavar='max-reps',
        type=int,
        default=400,
        help='The maximum number of inventory items to query for a network device. Default is 400.'
    )

    return parser.parse_args()


def get_usm_user_data() -> UsmUserData:
    """Create UsmUserData object for SNMPv3.

    Generate a UsmUserData object by prompting the user for various SNMPv3
    details.

    Returns:
        A pysnmp.hlapi.UsmUserData object.
    """
    snmp_v3_methods = {
        '1': 'authPriv',
        '2': 'authNoPriv',
        '3': 'noAuthNoPriv',
    }
    snmp_auth_proto = {
        '1': 'usmHMACMD5AuthProtocol',
        '2': 'usmHMACSHAAuthProtocol',
        '3': 'usmHMAC128SHA224AuthProtocol',
        '4': 'usmHMAC192SHA256AuthProtocol',
        '5': 'usmHMAC256SHA384AuthProtocol',
        '6': 'usmHMAC384SHA512AuthProtocol',
    }
    snmp_priv_proto = {
        '1': 'usmDESPrivProtocol',
        '2': 'usm3DESEDEPrivProtocol',
        '3': 'usmAesCfb128Protocol',
        '4': 'usmAesCfb192Protocol',
        '5': 'usmAesCfb256Protocol',
    }

    user = input('SNMPv3 User: ')

    print('Available SNMPv3 Methods:')
    for opt, v3_method in snmp_v3_methods.items():
        print(f'\tOption {opt}: {v3_method}')

    try:
        while True:
            method_opt = input('Option: ')
            if method_opt not in snmp_v3_methods:
                print('Invalid option. Try again or CTRL+C to quit.')
            else:
                break
    except KeyboardInterrupt:
        sys.exit()

    # Obtain Auth protocol and key
    if method_opt in ['1', '2']:
        print('Available SNMPv3 Auth Protocols:')
        for opt, auth_proto in snmp_auth_proto.items():
            print(f'\tOption {opt}: {auth_proto}')

        try:
            while True:
                auth_proto_opt = input('Option: ')
                if auth_proto_opt not in snmp_auth_proto:
                    print('Invalid option. Try again or CTRL+C to quit.')
                else:
                    break
        except KeyboardInterrupt:
            sys.exit()

    if auth_proto_opt == '1':
        from pysnmp.hlapi import usmHMACMD5AuthProtocol
        auth_proto = usmHMACMD5AuthProtocol
    elif auth_proto_opt == '2':
        from pysnmp.hlapi import usmHMACSHAAuthProtocol
        auth_proto = usmHMACSHAAuthProtocol
    elif auth_proto_opt == '3':
        from pysnmp.hlapi import usmHMAC128SHA224AuthProtocol
        auth_proto = usmHMAC128SHA224AuthProtocol
    elif auth_proto_opt == '4':
        from pysnmp.hlapi import usmHMAC192SHA256AuthProtocol
        auth_proto = usmHMAC192SHA256AuthProtocol
    elif auth_proto_opt == '5':
        from pysnmp.hlapi import usmHMAC256SHA384AuthProtocol
        auth_proto = usmHMAC256SHA384AuthProtocol
    elif auth_proto_opt == '6':
        from pysnmp.hlapi import usmHMAC384SHA512AuthProtocol
        auth_proto = usmHMAC384SHA512AuthProtocol
    else:
        auth_proto = usmNoAuthProtocol

    if auth_proto != usmNoAuthProtocol:
        auth_key = getpass('SNMPv3 Auth Key: ')
    else:
        auth_key = None

    # Obtain Priv protocol and key
    if method_opt in ['1']:
        print('Available SNMPv3 Priv Protocols:')
        for opt, priv_proto in snmp_priv_proto.items():
            print(f'\tOption {opt}: {priv_proto}')

        try:
            while True:
                priv_proto_opt = input('Option: ')
                if priv_proto_opt not in snmp_priv_proto:
                    print('Invalid option. Try again or CTRL+C to quit.')
                else:
                    break
        except KeyboardInterrupt:
            sys.exit()

    if priv_proto_opt == '1':
        from pysnmp.hlapi import usmDESPrivProtocol
        priv_proto = usmDESPrivProtocol
    elif priv_proto_opt == '2':
        from pysnmp.hlapi import usm3DESEDEPrivProtocol
        priv_proto = usm3DESEDEPrivProtocol
    elif priv_proto_opt == '3':
        from pysnmp.hlapi import usmAesCfb128Protocol
        priv_proto = usmAesCfb128Protocol
    elif priv_proto_opt == '4':
        from pysnmp.hlapi import usmAesCfb192Protocol
        priv_proto = usmAesCfb192Protocol
    elif priv_proto_opt == '5':
        from pysnmp.hlapi import usmAesCfb256Protocol
        priv_proto = usmAesCfb256Protocol
    else:
        priv_proto = usmNoPrivProtocol

    if priv_proto != usmNoPrivProtocol:
        priv_key = getpass('SNMPv3 Priv Key: ')
    else:
        priv_key = None

    auth = UsmUserData(
        userName=user,
        authKey=auth_key,
        authProtocol=auth_proto,
        privKey=priv_key,
        privProtocol=priv_proto)

    return auth


def create_community_data(version: str) -> CommunityData:
    """Create a PySNMP CommunityData object.

    Args:
        version: An SNMP version, either 'v1' or 'v2c'.

    Returns:
        A pysnmp.hlapi.CommunityData object.

    Raises:
        InvalidSnmpVersion
    """
    community = getpass('Community String: ')
    mpmodels = {'v1': 0, 'v2c': 1}
    if version not in mpmodels:
        raise InvalidSnmpVersion

    return CommunityData(community, mpModel=mpmodels[version])


def get_pysnmp_auth_object() -> Union[UsmUserData, CommunityData]:
    """Create PySNMP auth object.

    This function creates a PySNMP auth type object of either UsmUserData
    (for SNMP v3) or CommunityData (for SNMP v1/v2c), based on the user input.

    Returns:
        A UsmUserData or CommunityData object.
    """
    snmp_vers = {
        '1': 'v1',
        '2': 'v2c',
        '3': 'v3',
    }
    auth = None

    print('Available SNMP Versions:')
    for opt, version in snmp_vers.items():
        print(f'\tOption {opt}: SNMP {version}')

    try:
        while True:
            selected_opt = input('Option: ')
            if selected_opt not in snmp_vers:
                print('Invalid option. Try again or CTRL+C to quit.')
            else:
                break
    except KeyboardInterrupt:
        sys.exit()

    if selected_opt in ['1', '2']:
        auth = create_community_data(snmp_vers[selected_opt])
    elif selected_opt == '3':
        auth = get_usm_user_data()

    return auth


def create_mib_browser() -> view.MibViewController:
    """Create a MIB browser.

    Create a MIB browser for ENTITY-MIB so that MIB labels can be parsed.

    Returns:
        A MIB view controller for the ENTITY-MIB.
    """
    mib_builder = builder.MibBuilder()
    compiler.addMibCompiler(mib_builder, sources=[MIB_FILE_SOURCE, ])
    mib_builder.loadModules('ENTITY-MIB',)
    mib_view = view.MibViewController(mib_builder)

    return mib_view


def get_ent_physical_table(auth: Union[UsmUserData, CommunityData], ip: str, mib_view: view.MibViewController, max_reps: int = 400) -> Dict:
    """Get the entPhysicalTable of a device.

    Args:
        auth: An auth object of type UsmUserData or CommunityData.
        ip: The IP address of the host to query.
        mib_view: A PySNMP MibViewController for parsing response PySNMP ObjectName objects.
        max_reps: The maximum number of MIB variables to query.

    Returns:
        A dictionary keyed off of the entPhysicalIndex followed by the various
        entPhysicalEntry object names (e.g. entPhysicalDescr, entPhysicalName, etc.)
        and their values.
    """
    ent_physical_table = {}

    # Build PySNMP object from ENTITY-MIB.my file instead of a compiled MIB
    object_type = ObjectType(ObjectIdentity(
        'ENTITY-MIB', 'entPhysicalTable'
    ).addAsn1MibSource(MIB_FILE_SOURCE))

    iterator = bulkCmd(
        SnmpEngine(),
        auth,
        UdpTransportTarget((ip, 161)),
        ContextData(),
        0, max_reps,
        object_type,
    )

    print(f'Querying device {ip}')
    error_indication, error_status, error_index, var_binds = next(iterator)

    if error_indication:
        print(f'Error experienced with host {ip}:\n{error_indication}')
    elif error_status:
        print('{} at {}'.format(error_status.prettyPrint(),
                                error_index and var_binds[int(error_index) - 1][0] or '?'))

    for var_bind in var_binds:
        oid, label, suffix = mib_view.getNodeName((var_bind[0]))

        # Get entPhysicalEntry object name
        obj_name = label[-1]

        # Get the entPhysicalIndex value
        phy_index = suffix.prettyPrint()

        # Update table dict with object entry, using entPhysicalIndex as the key
        if suffix not in ent_physical_table:
            ent_physical_table[phy_index] = {}
        ent_physical_table[phy_index][obj_name
                                      ] = var_bind[1].prettyPrint()

    return ent_physical_table


def main() -> None:
    """Initialize script"""
    args = get_args()
    devices = []
    hw_inventory = {}

    with open(args.i, mode='r', encoding='UTF-8') as fh:
        for device in fh.readlines():
            devices.append(device.strip())

    auth = get_pysnmp_auth_object()
    mib_view = create_mib_browser()

    for device in devices:
        hw = get_ent_physical_table(auth, device, mib_view, args.m)
        hw_inventory[device] = hw

    FNAME = 'hw_inventory.csv'
    with open(FNAME, 'w') as fh:
        csv_writer = csv.writer(
            fh, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        csv_writer.writerow(['Device',
                             'entPhysicalIndex',
                             'entPhysicalDescr',
                             'entPhysicalVendorType',
                             'entPhysicalContainedIn',
                             'entPhysicalClass',
                             'entPhysicalParentRelPos',
                             'entPhysicalName',
                             'entPhysicalHardwareRev',
                             'entPhysicalFirmwareRev',
                             'entPhysicalSoftwareRev',
                             'entPhysicalSerialNum',
                             'entPhysicalMfgName',
                             'entPhysicalModelName',
                             'entPhysicalAlias',
                             'entPhysicalAssetID',
                             'entPhysicalIsFRU',
                             'entPhysicalMfgDate',
                             'entPhysicalUris', ])

        for device, inventory in hw_inventory.items():
            for phy_index, components in inventory.items():
                csv_writer.writerow([
                    device,
                    phy_index,
                    components.get('entPhysicalDescr', ''),
                    components.get('entPhysicalVendorType', ''),
                    components.get('entPhysicalContainedIn', ''),
                    components.get('entPhysicalClass', ''),
                    components.get('entPhysicalParentRelPos', ''),
                    components.get('entPhysicalName', ''),
                    components.get('entPhysicalHardwareRev', ''),
                    components.get('entPhysicalFirmwareRev', ''),
                    components.get('entPhysicalSoftwareRev', ''),
                    components.get('entPhysicalSerialNum', ''),
                    components.get('entPhysicalMfgName', ''),
                    components.get('entPhysicalModelName', ''),
                    components.get('entPhysicalAlias', ''),
                    components.get('entPhysicalAssetID', ''),
                    components.get('entPhysicalIsFRU', ''),
                    components.get('entPhysicalMfgDate', ''),
                    components.get('entPhysicalUris', ''),
                ])

    print(f'Results written to {FNAME}')


if __name__ == '__main__':
    main()
