# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Service Install Helper library used by psexec and smbrelayx
# You provide an already established connection and an exefile
# (or class that mimics a file class) and this will install and
# execute the service, and then uninstall (install(), uninstall().
# It tries to take care as much as possible to leave everything clean.
#
# Author:
#  Alberto Solino (@agsolino)
#

import random
import string

from impacket.dcerpc.v5 import transport, srvs, scmr
from impacket import smb,smb3, LOG
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_WRITE_DATA, FILE_DIRECTORY_FILE

class ServiceInstall:
    def __init__(self, SMBObject, exeFile, serviceName='', binary_service_name=None):
        self._rpctransport = 0
        self.__service_name = (
            serviceName
            if len(serviceName) > 0
            else ''.join([random.choice(string.ascii_letters) for _ in range(4)])
        )


        if binary_service_name is None:
            self.__binary_service_name = (
                ''.join([random.choice(string.ascii_letters) for _ in range(8)])
                + '.exe'
            )

        else:
            self.__binary_service_name = binary_service_name

        self.__exeFile = exeFile

        # We might receive two different types of objects, always end up
        # with a SMBConnection one
        if isinstance(SMBObject, (smb.SMB, smb3.SMB3)):
            self.connection = SMBConnection(existingConnection = SMBObject)
        else:
            self.connection = SMBObject

        self.share = ''

    def getShare(self):
        return self.share

    def getShares(self):
        # Setup up a DCE SMBTransport with the connection already in place
        LOG.info(f"Requesting shares on {self.connection.getRemoteHost()}.....")
        try:
            self._rpctransport = transport.SMBTransport(self.connection.getRemoteHost(),
                                                        self.connection.getRemoteHost(),filename = r'\srvsvc',
                                                        smb_connection = self.connection)
            dce_srvs = self._rpctransport.get_dce_rpc()
            dce_srvs.connect()

            dce_srvs.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrShareEnum(dce_srvs, 1)
            return resp['InfoStruct']['ShareInfo']['Level1']
        except:
            LOG.critical(
                f"Error requesting shares on {self.connection.getRemoteHost()}, aborting....."
            )

            raise


    def createService(self, handle, share, path):
        LOG.info(
            f"Creating service {self.__service_name} on {self.connection.getRemoteHost()}....."
        )


        # First we try to open the service in case it exists. If it does, we remove it.
        try:
            resp =  scmr.hROpenServiceW(self.rpcsvc, handle, self.__service_name+'\x00')
        except Exception as e:
            if str(e).find('ERROR_SERVICE_DOES_NOT_EXIST') < 0:
                raise e
        else:
            # It exists, remove it
            scmr.hRDeleteService(self.rpcsvc, resp['lpServiceHandle'])
            scmr.hRCloseServiceHandle(self.rpcsvc, resp['lpServiceHandle'])

        # Create the service
        command = '%s\\%s' % (path, self.__binary_service_name)
        try:
            resp = scmr.hRCreateServiceW(self.rpcsvc, handle,self.__service_name + '\x00', self.__service_name + '\x00',
                                         lpBinaryPathName=command + '\x00', dwStartType=scmr.SERVICE_DEMAND_START)
        except:
            LOG.critical(
                f"Error creating service {self.__service_name} on {self.connection.getRemoteHost()}"
            )

            raise
        else:
            return resp['lpServiceHandle']

    def openSvcManager(self):
        LOG.info(f"Opening SVCManager on {self.connection.getRemoteHost()}.....")
        # Setup up a DCE SMBTransport with the connection already in place
        self._rpctransport = transport.SMBTransport(self.connection.getRemoteHost(), self.connection.getRemoteHost(),
                                                    filename = r'\svcctl', smb_connection = self.connection)
        self.rpcsvc = self._rpctransport.get_dce_rpc()
        self.rpcsvc.connect()
        self.rpcsvc.bind(scmr.MSRPC_UUID_SCMR)
        try:
            resp = scmr.hROpenSCManagerW(self.rpcsvc)
        except:
            LOG.critical(
                f"Error opening SVCManager on {self.connection.getRemoteHost()}....."
            )

            raise Exception('Unable to open SVCManager')
        else:
            return resp['lpScHandle']

    def copy_file(self, src, tree, dst):
        LOG.info(f"Uploading file {dst}")
        fh = open(src, 'rb') if isinstance(src, str) else src
        f = dst
        pathname = f.replace('/','\\')
        try:
            self.connection.putFile(tree, pathname, fh.read)
        except:
            LOG.critical(f"Error uploading file {dst}, aborting.....")
            raise
        fh.close()

    def findWritableShare(self, shares):
        # Check we can write a file on the shares, stop in the first one
        writeableShare = None
        for i in shares['Buffer']:
            if i['shi1_type'] in [srvs.STYPE_DISKTREE, srvs.STYPE_SPECIAL]:
                share = i['shi1_netname'][:-1]
                tid = 0
                try:
                    tid = self.connection.connectTree(share)
                    self.connection.openFile(tid, '\\', FILE_WRITE_DATA, creationOption=FILE_DIRECTORY_FILE)
                except:
                    LOG.debug('Exception', exc_info=True)
                    LOG.critical("share '%s' is not writable." % share)
                else:
                    LOG.info(f'Found writable share {share}')
                    writeableShare = str(share)
                    break
                finally:
                    if tid != 0:
                        self.connection.disconnectTree(tid)
        return writeableShare

    def install(self):
        if self.connection.isGuestSession():
            LOG.critical("Authenticated as Guest. Aborting")
            self.connection.logoff()
            del self.connection
        else:
            fileCopied = False
            serviceCreated = False
            # Do the stuff here
            try:
                # Let's get the shares
                shares = self.getShares()
                self.share = self.findWritableShare(shares)
                if self.share is None:
                    return False
                self.copy_file(self.__exeFile ,self.share,self.__binary_service_name)
                fileCopied = True
                svcManager = self.openSvcManager()
                if svcManager != 0:
                    serverName = self.connection.getServerName()
                    if self.share.lower() == 'admin$':
                        path = '%systemroot%'
                    elif serverName == '':
                        path = '\\\\127.0.0.1\\' + self.share
                    else:
                        path = '\\\\%s\\%s' % (serverName, self.share)
                    service = self.createService(svcManager, self.share, path)
                    serviceCreated = True
                    if service != 0:
                        # Start service
                        LOG.info(f'Starting service {self.__service_name}.....')
                        try:
                            scmr.hRStartServiceW(self.rpcsvc, service)
                        except:
                            pass
                        scmr.hRCloseServiceHandle(self.rpcsvc, service)
                    scmr.hRCloseServiceHandle(self.rpcsvc, svcManager)
                    return True
            except Exception as e:
                LOG.critical(f"Error performing the installation, cleaning up: {e}")
                LOG.debug("Exception", exc_info=True)
                try:
                    scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
                except:
                    pass
                if fileCopied:
                    try:
                        self.connection.deleteFile(self.share, self.__binary_service_name)
                    except:
                        pass
                if serviceCreated:
                    try:
                        scmr.hRDeleteService(self.rpcsvc, service)
                    except:
                        pass
            return False

    def uninstall(self):
        fileCopied = True
        serviceCreated = True
        # Do the stuff here
        try:
            # Let's get the shares
            svcManager = self.openSvcManager()
            if svcManager != 0:
                resp = scmr.hROpenServiceW(self.rpcsvc, svcManager, self.__service_name+'\x00')
                service = resp['lpServiceHandle']
                LOG.info(f'Stopping service {self.__service_name}.....')
                try:
                    scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
                except:
                    pass
                LOG.info(f'Removing service {self.__service_name}.....')
                scmr.hRDeleteService(self.rpcsvc, service)
                scmr.hRCloseServiceHandle(self.rpcsvc, service)
                scmr.hRCloseServiceHandle(self.rpcsvc, svcManager)
            LOG.info(f'Removing file {self.__binary_service_name}.....')
            self.connection.deleteFile(self.share, self.__binary_service_name)
        except Exception:
            LOG.critical("Error performing the uninstallation, cleaning up" )
            try:
                scmr.hRControlService(self.rpcsvc, service, scmr.SERVICE_CONTROL_STOP)
            except:
                pass
            if fileCopied:
                try:
                    self.connection.deleteFile(self.share, self.__binary_service_name)
                except:
                    try:
                        self.connection.deleteFile(self.share, self.__binary_service_name)
                    except:
                        pass
            if serviceCreated:
                try:
                    scmr.hRDeleteService(self.rpcsvc, service)
                except:
                    pass
