# IMPORTS #
import logging

from impacket.dcerpc.v5 import transport, samr
from impacket.nt_errors import STATUS_MORE_ENTRIES
from impacket.dcerpc.v5.rpcrt import DCERPCException
from exceptions import *


class SamrListCreate:
    """
    Use samr protocol to create or list users and groups
    """

    MACHINE_DOMAIN = 0
    BUILTIN_DOMAIN = 1

    def __init__(self, username='', password='', domain='', hashes=None,
                 aes_key=None, do_kerberos=False, kdc_host=None, port=445):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aes_key = aes_key
        self.__do_kerberos = do_kerberos
        self.__kdc_host = kdc_host
        self.__port = port

        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def __set_rpc_connection(self, remote_name, remote_host):
        """
        Create an rpc session
        :param remote_name: 
        :param remote_host: 
        :return: 
        """
        string_binding = r'ncacn_np:%s[\pipe\samr]' % remote_name
        logging.debug('StringBinding %s' % string_binding)
        rpc_transport = transport.DCERPCTransportFactory(string_binding)
        rpc_transport.set_dport(self.__port)
        rpc_transport.setRemoteHost(remote_host)

        if hasattr(rpc_transport, 'set_credentials'):
            # This method exists only for selected protocol sequences.
            rpc_transport.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash,
                                          self.__nthash, self.__aes_key)
        rpc_transport.set_kerberos(self.__do_kerberos, self.__kdc_host)
        return rpc_transport

    @staticmethod
    def __dce_connect(rpc_transport):
        """
        Create and bind an RPC session to remote host
        :param rpc_transport: (DCERPCTransportFactory) RPC session settings
        :return: DCE/RPC session
        """
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)
        return dce

    @staticmethod
    def __dce_disconnect(dce):
        dce.disconnect()

    @staticmethod
    def __obtain_domain_handle(dce, domain_id=MACHINE_DOMAIN):
        """
        Obtain domain handle for samr protocol commands
        :param dce: DCE/RPC object
        :param domain_id: Domain ID to use MACHINE/BUILTIN
        :return: (bytes) domain handle
        """
        resp = samr.hSamrConnect(dce)
        server_handle = resp['ServerHandle']

        resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
        domains = resp['Buffer']['Buffer']

        # Two domain will be found, BUILTIN and MACHINE
        print('Found domain(s):')
        for domain in domains:
            print(" . %s" % domain['Name'])

        logging.info("Using domain %s" % domains[domain_id]['Name'])

        resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domains[domain_id]['Name'])

        resp = samr.hSamrOpenDomain(dce, serverHandle=server_handle, domainId=resp['DomainId'],
                                    desiredAccess=samr.MAXIMUM_ALLOWED)
        domain_handle = resp['DomainHandle']

        return domain_handle

    def list_users(self, remote_name, remote_host):
        """
        List users
        :param remote_name: (string) remote name to use in rpc connection string
        :param remote_host: (string) remote host to connect to
        :return: (list) List of users found, each item contains (userName, RelativeId, UserAllInfo)
        """
        # Create an DCE/RPC session
        rpc_transport = self.__set_rpc_connection(remote_name, remote_host)
        dce = self.__dce_connect(rpc_transport)
        entries = []

        try:
            # Obtain domain handle
            domain_handle = self.__obtain_domain_handle(dce)
            status = STATUS_MORE_ENTRIES
            enumeration_context = 0
            while status == STATUS_MORE_ENTRIES:
                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle, enumerationContext=enumeration_context)
                except DCERPCException as e:
                    if str(e).find('STATUS_MORE_ENTRIES') < 0:
                        raise ListUsersException(e)

                for user in resp['Buffer']['Buffer']:
                    # Get user information for each user
                    r = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user['RelativeId'])
                    info = samr.hSamrQueryInformationUser2(dce, r['UserHandle'],
                                                           samr.USER_INFORMATION_CLASS.UserAllInformation)
                    entry = (user['Name'], user['RelativeId'], info['Buffer']['All'])
                    entries.append(entry)
                    samr.hSamrCloseHandle(dce, r['UserHandle'])

                enumeration_context = resp['EnumerationContext']
                status = resp['ErrorCode']

        except ListUsersException as e:
            logging.critical("Error listing users: %s" % e)

        dce.disconnect()

        return entries

    def list_groups(self, remote_name, remote_host):
        """
        List groups
        :param remote_name: (string) remote name to use in rpc connection string
        :param remote_host: (string) remote host to connect to
        :return: (list) List of local groups found, each item contains (groupName, RelativeId, GroupGeneralInfo) 
        """
        rpc_transport = self.__set_rpc_connection(remote_name, remote_host)
        dce = self.__dce_connect(rpc_transport)
        entries = []

        try:
            # Acquire domain handles for BUILTIN and MACHINE domain
            domain_handles = [self.__obtain_domain_handle(dce, self.BUILTIN_DOMAIN),
                              self.__obtain_domain_handle(dce, self.MACHINE_DOMAIN)]

            for domain_handle in domain_handles:
                status = STATUS_MORE_ENTRIES
                enumeration_context = 0
                while status == STATUS_MORE_ENTRIES:
                    try:
                        resp = samr.hSamrEnumerateAliasesInDomain(dce, domain_handle,
                                                                  enumerationContext=enumeration_context)
                    except DCERPCException as e:
                        if str(e).find('STATUS_MORE_ENTRIES') < 0:
                            raise ListGroupException(e)

                    for group in resp['Buffer']['Buffer']:
                        # Get group information for each group
                        r = samr.hSamrOpenAlias(dce, domain_handle, samr.MAXIMUM_ALLOWED, group['RelativeId'])

                        info = samr.hSamrQueryInformationAlias(dce, r['AliasHandle'],
                                                               samr.ALIAS_INFORMATION_CLASS.AliasGeneralInformation)
                        entry = (group['Name'], group['RelativeId'], info['Buffer']['General'])
                        entries.append(entry)
                        samr.hSamrCloseHandle(dce, r['AliasHandle'])

                    enumeration_context = resp['EnumerationContext']
                    status = resp['ErrorCode']

        except ListGroupException as e:
            logging.critical("Error listing users: %s" % e)

        dce.disconnect()

        return entries

    def create_user(self, remote_name, remote_host, name, account_type):
        """
        Create new user
        :param remote_name: (string) remote name to use in rpc connection string
        :param remote_host: (string) remote host to connect to
        :param name: (string) name of user to be created
        :param account_type: account type USER_NORMAL_ACCOUNT | USER_WORKSTATION_TRUST_ACCOUNT | USER_SERVER_TRUST_ACCOUNT
        :return: None, exception will be raised on error
        """
        # Create rpc
        rpc_transport = self.__set_rpc_connection(remote_name, remote_host)

        # Create dce connection
        dce = self.__dce_connect(rpc_transport)

        try:
            # Acquire domainHandle
            domain_handle = self.__obtain_domain_handle(dce)
            try:
                # Create user request
                resp = samr.hSamrCreateUser2InDomain(dce, domain_handle, name, accountType=account_type)
                logging.info("User {name} was created successfully with relative ID: {relative_id}".format(
                    name=name, relative_id=resp['RelativeId']))
            except DCERPCException as e:
                raise AddUserException(e)

        except AddUserException as e:
            logging.critical("Error Create user: %s" % e)

        # Close dce connection
        self.__dce_disconnect(dce)

    def create_group(self, remote_name, remote_host, name):
        """
        Create new local group
        :param remote_name: (string) remote name to use in rpc connection string
        :param remote_host: (string) remote host to connect to
        :param name: (string) name of group to be created
        :return: None, exception will be raised on error
        """
        # Create rpc
        rpc_transport = self.__set_rpc_connection(remote_name, remote_host)

        # Create dce connection
        dce = self.__dce_connect(rpc_transport)

        try:
            # Acquire domainHandle
            domain_handle = self.__obtain_domain_handle(dce)
            try:
                # Create local group request
                resp = samr.hSamrCreateAliasInDomain(dce, domain_handle, name)
                logging.info("Group {name} was created successfully with relative id {relative_id}".format(
                    name=name, relative_id=resp['RelativeId']))
            except DCERPCException as e:
                raise AddGroupException(e)

        except AddGroupException as e:
            logging.critical("Error Create group: %s" % e)

        # Close dce connection
        self.__dce_disconnect(dce)
