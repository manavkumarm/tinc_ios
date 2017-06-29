//
//  TincVPNTunnelProvider.swift
//  TestLibTincd
//
//  Created by Manav Kumar Mehta on 6/10/17.
//  Copyright © 2017 Elear Solutions Tech. Pvt. Ltd. All rights reserved.
//

import Foundation
import NetworkExtension

public func withArrayOfCStrings<R>(
    _ args: [String],
    _ body: (UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>!) -> R
    ) -> R {
    var cStrings = args.map { strdup($0) }
    cStrings.append(nil)
    defer {
        cStrings.forEach { free($0) }
    }
    return body(UnsafeMutablePointer(mutating: cStrings))
}

class TincVPNTunnelProvider: NEPacketTunnelProvider {
    
    // VPN Tunnel Configuration Settings - update this before running this App for your environment
    let remoteTunnelIPAddress: String = "192.168.43.51" // This is NOT used and is only needed for
                                                        // VPN tunnel config in iOS - this can be set
                                                        // to anything other than a loopback address
    let tunIP: String = "10.0.1.30"                 // TUN Interface configuration
    let tunSubnetMask: String = "255.255.255.0"
    let tunMTU: NSNumber = 1500
    let localRouteIP: String = "10.0.0.0"           // Config for routing packets to TUN interface
    let localRouteSubnet: String = "255.255.0.0"

    var readPathStr: UnsafeMutablePointer<Int8>!
    var pipePathStr: UnsafeMutablePointer<Int8>!
    var requestFd: Int32!
    var readFd: Int32!
    var writeFd: Int32!
    var pipeFd: Int32!
    
    // Temporary path variables for Request and Write sockets
    var requestPathStr: UnsafeMutablePointer<Int8>!
    var writePathStr: UnsafeMutablePointer<Int8>!
    
    // Override method to handle incoming VPN connections
    override func startTunnel(options: [String : NSObject]? = nil,
                              completionHandler: @escaping (Error?) -> Void) {
        
        // Set up VPN Tunnel
        NSLog("Configuring VPN Tunnel")
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: self.remoteTunnelIPAddress)
        settings.iPv4Settings = NEIPv4Settings(addresses: [ self.tunIP ],
                                               subnetMasks: [ self.tunSubnetMask ])
        let localRoute = NEIPv4Route(destinationAddress: self.localRouteIP,
                                     subnetMask: self.localRouteSubnet)
        settings.iPv4Settings?.includedRoutes = [ localRoute ]
        settings.iPv4Settings?.excludedRoutes = nil
        settings.mtu = self.tunMTU
        self.setTunnelNetworkSettings(settings) { err in
            if (nil != err) {
                NSLog("Tunnel Network Setting failed: %s", err!.localizedDescription)
                completionHandler(err)
                return
            } else {
                // Set up Request Socket to communicate with Tinc Daemon
                NSLog("Setting up sockets")
                self.requestFd = socket(PF_UNIX, SOCK_STREAM, 0)
                if (-1 == self.requestFd) {
                    NSLog("Request Socket create failed with error: %s", strerror(errno))
                    var reqSockErr: Error? = NSError(domain: "Request Socket Create Failure",
                                                     code: 1000,
                                                     userInfo: nil) as Error?
                    completionHandler(reqSockErr)
                }
                
                var reqSaAddr = sockaddr_un()
                let tincdReqSocketFile = "tincdreq.socket"
                var reqPathStr = strdup((FileManager.default.containerURL(
                                            forSecurityApplicationGroupIdentifier: "group.solutions.elear.Tincd")?.path)! +
                                        "/" + tincdReqSocketFile)
                memset(&reqSaAddr, 0, MemoryLayout<sockaddr_un>.size)
                reqSaAddr.sun_family = sa_family_t(AF_UNIX)
                _ = withUnsafeMutablePointer(to: &reqSaAddr.sun_path) { ptr in
                    _ = ptr.withMemoryRebound(to: Int8.self, capacity: 1) { ptr in
                        strcpy(unsafeBitCast(ptr, to: UnsafeMutablePointer<Int8>!.self),
                               reqPathStr)
                    }
                }

                // Temporarily copy Request socket path to instance member
                self.requestPathStr = strdup(reqPathStr)
                
                var disableSigPipe: Int32 = 1
                let reqSockOptSigPipeStat = setsockopt(self.requestFd, SOL_SOCKET, SO_NOSIGPIPE,
                                                       &disableSigPipe,
                                                       socklen_t(MemoryLayout<Int32>.size))
                if (-1 == reqSockOptSigPipeStat) {
                    NSLog("Req setsockopt(SO_NOSIGPIPE) failed with error: %s", strerror(errno))
                }
                
                var sock_timeout = timeval()
                sock_timeout.tv_sec = 20
                let reqRcvTimeoutStat = setsockopt(self.requestFd, SOL_SOCKET, SO_RCVTIMEO,
                                                    &sock_timeout,
                                                    socklen_t(MemoryLayout<timeval>.size))
                if (-1 == reqRcvTimeoutStat) {
                    NSLog("Req setsockopt(SO_RCVTIMEO) failed with error: %s", strerror(errno))
                }
                let reqSendTimeoutStat = setsockopt(self.requestFd, SOL_SOCKET, SO_SNDTIMEO,
                                                     &sock_timeout,
                                                     socklen_t(MemoryLayout<timeval>.size))
                if (-1 == reqSendTimeoutStat) {
                    NSLog("Req setsockopt(SO_SNDTIMEO) failed with error: %s", strerror(errno))
                }

                // Open a socket for the Tinc Daemon to write to (i.e. for us to read from)
                self.readFd = socket(PF_UNIX, SOCK_DGRAM, 0)
                if (-1 == self.readFd) {
                    NSLog("Read Socket create failed with error: %s", strerror(errno))
                    var readSockErr: Error? = NSError(domain: "Read Socket Create Failure",
                                                      code: 1002,
                                                      userInfo: nil) as Error?
                    completionHandler(readSockErr)
                }
                
                var readSaAddr = sockaddr_un()
                let tincdReadSocketFile = "tincdread.socket"
                self.readPathStr = strdup((FileManager.default.containerURL(
                                            forSecurityApplicationGroupIdentifier: "group.solutions.elear.Tincd")?.path)! +
                                            "/" + tincdReadSocketFile)
                memset(&readSaAddr, 0, MemoryLayout<sockaddr_un>.size)
                readSaAddr.sun_family = sa_family_t(AF_UNIX)
                _ = withUnsafeMutablePointer(to: &readSaAddr.sun_path) { ptr in
                    _ = ptr.withMemoryRebound(to: Int8.self, capacity: 1) { ptr in
                        strcpy(unsafeBitCast(ptr, to: UnsafeMutablePointer<Int8>!.self),
                               self.readPathStr)
                    }
                }
                
                let readUnlinkStat = unlink(self.readPathStr)
                if (-1 == readUnlinkStat) {
                    NSLog("Read Socket unlink failed with error: %s", strerror(errno))
                }

                var reuseAddr: Int32 = 1
                let readSockOptReuseAddrStat = setsockopt(self.readFd, SOL_SOCKET, SO_REUSEADDR,
                                                          &reuseAddr,
                                                          socklen_t(MemoryLayout<Int32>.size))
                if (-1 == readSockOptReuseAddrStat) {
                    NSLog("Read setsockopt(SO_REUSEADDR) failed with error: %s", strerror(errno))
                }
                
                let readSockOptSigPipeStat = setsockopt(self.readFd, SOL_SOCKET, SO_NOSIGPIPE,
                                                               &disableSigPipe,
                                                               socklen_t(MemoryLayout<Int32>.size))
                if (-1 == readSockOptSigPipeStat) {
                    NSLog("Read setsockopt(SO_NOSIGPIPE) failed with error: %s", strerror(errno))
                }
                
                let readBindStat = withUnsafePointer(to: &readSaAddr) { ptr in
                    bind(self.readFd,
                         unsafeBitCast(ptr, to: UnsafePointer<sockaddr>!.self),
                         socklen_t(MemoryLayout<sockaddr_un>.size))
                }
                if (-1 == readBindStat) {
                    NSLog("Read Socket bind failed with error: %s", strerror(errno))
                    var readBindErr: Error? = NSError(domain: "Read Socket Bind Failure",
                                                      code: 1003,
                                                      userInfo: nil) as Error?
                    completionHandler(readBindErr)
                }
                
                // Open socket for Tinc Daemon to read from (i.e. for us to write to)
                self.writeFd = socket(PF_UNIX, SOCK_DGRAM, 0)
                if (-1 == self.writeFd) {
                    NSLog("Write Socket create failed with error: %s", strerror(errno))
                    var writeSockErr: Error? = NSError(domain: "Write Socket Create Failure",
                                                       code: 1002,
                                                       userInfo: nil) as Error?
                    completionHandler(writeSockErr)
                }
                
                let writeSockOptSigPipeStat = setsockopt(self.writeFd, SOL_SOCKET, SO_NOSIGPIPE,
                                                        &disableSigPipe,
                                                        socklen_t(MemoryLayout<Int32>.size))
                if (-1 == writeSockOptSigPipeStat) {
                    NSLog("Write setsockopt(SO_NOSIGPIPE) failed with error: %s", strerror(errno))
                }
                
                let writeSendTimeoutStat = setsockopt(self.writeFd, SOL_SOCKET, SO_SNDTIMEO,
                                                     &sock_timeout,
                                                     socklen_t(MemoryLayout<timeval>.size))
                if (-1 == writeSendTimeoutStat) {
                    NSLog("Write setsockopt(SO_SNDTIMEO) failed with error: %s", strerror(errno))
                }
                
                // Create a named pipe to communicate with containing app
                NSLog("Creating named pipe to communicate with containing App")
                let pipeFile = "tincd.pipe"
                self.pipePathStr = strdup((FileManager.default.containerURL(
                                                        forSecurityApplicationGroupIdentifier: "group.solutions.elear.Tincd")?.path)! +
                                    "/" + pipeFile)
                let pipeUnlinkStat = unlink(self.pipePathStr!)
                if (-1 == pipeUnlinkStat) {
                    NSLog("Pipe unlink failed due to error: %s", strerror(errno))
                }
                umask(0o000)
                let pipeCreateStat = mkfifo(self.pipePathStr!, 0o755)
                if (-1 == pipeCreateStat) {
                    NSLog("Pipe create failed due to error: %s", strerror(errno))
                    var pipeCreateErr: Error? = NSError(domain: "Pipe Create Failure",
                                                       code: 1002,
                                                       userInfo: nil) as Error?
                    completionHandler(pipeCreateErr)
                }

                // Create Request Packet for establishing UML connection with Tinc Daemon
                NSLog("Creating Request Packet for connecting to Tinc Daemon")
                enum requestType: UInt32 {
                    case REQ_NEW_CONTROL = 0
                }
                struct sockaddr_un_tinc {
                    var sun_len: UInt8!
                    var sun_family: sa_family_t
                    var sun_path: ( CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar,
                                    CChar, CChar, CChar, CChar, CChar, CChar, CChar, CChar )
                }
                struct writeRequest {
                    var magic: UInt32
                    var version: UInt32
                    var type: UInt32
                    var sock: sockaddr_un_tinc!
                }
                var writeReq = writeRequest(magic: 0xfeedface,
                                            version: 3,
                                            type: UInt32(requestType.REQ_NEW_CONTROL.rawValue),
                                            sock: sockaddr_un_tinc(sun_len: 0,
                                                                   sun_family: sa_family_t(AF_UNIX),
                                                                   sun_path:
                                                                    ( 0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0,
                                                                      0, 0, 0, 0, 0, 0, 0, 0 )
                                                                    )
                                            )
                _ = withUnsafeMutablePointer(to: &writeReq.sock.sun_path) { tempPtr in
                    _ = tempPtr.withMemoryRebound(to: Int8.self, capacity: 1) { ptr in
                        strcpy(ptr, self.readPathStr)
                    }
                }

                // Start up the Tinc Daemon
                var bkTincQueue: DispatchQueue?
                bkTincQueue = DispatchQueue(
                    label: "com.apple.queue",
                    qos: .background,
                    attributes: .concurrent,
                    autoreleaseFrequency: .inherit,
                    target: bkTincQueue
                )
                bkTincQueue?.async {
                    // Open named pipe to communicate with containing app
                    NSLog("Opening named pipe")
                    self.pipeFd = open(self.pipePathStr!, O_WRONLY)
                    if (-1 == self.pipeFd) {
                        NSLog("Pipe open failed due to error: %s", strerror(errno))
                        var pipeOpenErr: Error? = NSError(domain: "Pipe Open Failure",
                                                          code: 1002,
                                                          userInfo: nil) as Error?
                        completionHandler(pipeOpenErr)
                    }
                    
                    let pipeFcntlStat = fcntl(self.pipeFd, F_SETFL, O_NONBLOCK)
                    if (-1 == pipeFcntlStat) {
                        NSLog("Pipe fcntl(O_NONBLOCK) failed due to error: %s", strerror(errno))
                        var pipeFcntlErr: Error? = NSError(domain: "Pipe Fcntl Failure",
                                                          code: 1002,
                                                          userInfo: nil) as Error?
                        completionHandler(pipeFcntlErr)
                    }
                    
                    // Setup Handler for displaying Tinc Daemon log messages on the UI
                    // This writes the log message to the named pipe monitored by the
                    // containing App which then updates the UI
                    func setLogMessage(txt: UnsafePointer<Int8>?, pipeptr: UnsafeMutableRawPointer?)
                      -> Void {
                        var writePtr = txt
                        let pipeFd: Int32 = unsafeBitCast(pipeptr,
                                                          to: UnsafeMutablePointer<Int32>.self).pointee
                        var pipeWriteDone = false
                        var bytesToWrite = Int(strlen(txt) + 1) * MemoryLayout<Int8>.size
                        while (!pipeWriteDone) {
                            let bytesWritten = write(pipeFd,
                                                     unsafeBitCast(writePtr,
                                                                   to: UnsafeMutableRawPointer!.self),
                                                     bytesToWrite)
                            if (-1 == bytesWritten) {
                                NSLog("Pipe write failed due to error: %s", strerror(errno))
                                pipeWriteDone = true
                            } else if (bytesWritten == bytesToWrite) {
                                pipeWriteDone = true
                            } else {
                                writePtr = writePtr! + (MemoryLayout<Int8>.size * bytesWritten)
                                bytesToWrite = bytesToWrite - bytesWritten
                            }
                        } // while !pipeWriteDone
                    } // setLogMessage()
                    
                    // Invoke Tincd Library to set Callback Function pointer
                    // to the handler above
                    NSLog("Starting Tinc...")
                    var pipePtr = withUnsafeMutablePointer(to: &self.pipeFd!) { tempPtr in
                        unsafeBitCast(tempPtr, to: UnsafeMutableRawPointer?.self)
                    }
                    set_ios_log_cb(setLogMessage, pipePtr)
                    
                    // Set up command-line arguments for Tinc Daemon
                    // and invoke the Daemon by calling the corresponding Library method
                    let tincdArgs = [
                        "tincd",
                        "-n",
                        "coco-vpn",
                        "-d5",
                        "-o",
                        "Device=\(String(cString: reqPathStr!))",
                        "-o",
                        "DeviceType=uml",
                        "-o",
                        "Port=8004",
                        "-o",
                        "PingInterval=300"
                    ]
                    let argc = Int32(tincdArgs.count)
                    _ = withArrayOfCStrings(tincdArgs) {
                        argv in libtincd_main(argc, argv)
                    }
                }

                // Wait for Tinc to bind UML socket then connect to the socket
                NSLog("Waiting for Tinc Daemon to create UML socket")
                let socketTimeout = 10      // Exit if socket is not bound within this duration (in secs)
                let socketWait = 0.5        // Sleep interval between re-tries (in secs)
                let pipeWait = 0.5
                var socketElapsed = 0.0
                var socketDelay = timespec()
                socketDelay.tv_nsec = Int(socketWait * Double(1000000000))
                var socketFileInfo = stat()
                while (-1 == stat(self.requestPathStr!, &socketFileInfo)) {
                    if (socketElapsed == Double(socketTimeout)) {
                        NSLog("Timed out waiting for UML socket from Tinc")
                        exit(0)
                    }
                    nanosleep(&socketDelay, nil)
                    socketElapsed = socketElapsed + socketWait
                }
                NSLog("Connecting to Tinc")
                let reqConnStat = withUnsafePointer(to: &reqSaAddr) { ptr in
                    connect(self.requestFd,
                            unsafeBitCast(ptr, to: UnsafePointer<sockaddr>!.self),
                            socklen_t(MemoryLayout<sockaddr_un>.size))
                }
                if (-1 == reqConnStat) {
                    NSLog("Request Socket connection failed with error: %s", strerror(errno))
                    var reqConnErr: Error? = NSError(domain: "Request Socket Connection Failure",
                                                     code: 1001,
                                                     userInfo: nil) as Error?
                    completionHandler(reqConnErr)
                }
                
                // Send Tinc write socket (i.e. our read socket) details to Tinc Daemon, which will reply
                // with Tinc read socket (i.e. our write socket) details
                let writeReqWriteStat = withUnsafePointer(to: &writeReq) { pkt in
                    write(self.requestFd,
                          pkt,
                          MemoryLayout<writeRequest>.size)
                }
                if (-1 == writeReqWriteStat) {
                    NSLog("Request Socket write failed with error: %s", strerror(errno))
                    let writeReqErr: Error? = NSError(domain: "Request Socket Write Failure",
                                                      code: 1005,
                                                      userInfo: nil) as Error?
                    completionHandler(writeReqErr)
                    return
                }
                
                // Read details of Tinc Read socket (i.e. our write socket) from Tinc Daemon
                // which will be written on the Request socket
                /* var readDelay = timespec()
                let nanoSecsInSec: Double = 1000000
                readDelay.tv_nsec = Int(1 * nanoSecsInSec)
                nanosleep(&readDelay, nil) */  // wait for 250 millisecs before reading from Request socket
                var writeSaAddr = sockaddr_un()
                let reqReadStat = withUnsafeBytes(of: &writeSaAddr) { ptr in
                    read(self.requestFd,
                         unsafeBitCast(ptr.baseAddress!, to: UnsafeMutableRawPointer!.self),
                         MemoryLayout<sockaddr_un>.size)
                }
                if (-1 == reqReadStat) {
                    NSLog("Request Socket read failed with error: %s", strerror(errno))
                    let reqReadErr: Error? = NSError(domain: "Request Socket Read Failure",
                                                     code: 1007,
                                                     userInfo: nil) as Error?
                    completionHandler(reqReadErr)
                    return
                }

                // Temporarily copy Write socket path to instance member
                _ = withUnsafePointer(to: &writeSaAddr.sun_path) { tempPtr in
                    _ = tempPtr.withMemoryRebound(to: Int8.self, capacity: 1) { pathPtr in
                        self.writePathStr = strdup(pathPtr)
                    }
                }
                
                // Connect to Tinc Read socket (i.e. our write socket)
                let writeConnStat = withUnsafePointer(to: &writeSaAddr) { ptr in
                    connect(self.writeFd,
                            unsafeBitCast(ptr, to: UnsafePointer<sockaddr>!.self),
                            socklen_t(MemoryLayout<sockaddr_un>.size))
                }
                if (-1 == writeConnStat) {
                    NSLog("Write Socket connection failed with error: %s", strerror(errno))
                    var writeConnErr: Error? = NSError(domain: "Write Socket Connection Failure",
                                                     code: 1001,
                                                     userInfo: nil) as Error?
                    completionHandler(writeConnErr)
                }
                NSLog("UML connection to Tinc Established!")
                
                // UML Connection successfully established: Close the Request socket!
                let reqCloseStat = close(self.requestFd)
                if (-1 == reqCloseStat) {
                    NSLog("Request Socket close failed with error: %s", strerror(errno))
                }
                self.requestFd = nil
                // Temporary code to unlink Request socket path
                unlink(self.requestPathStr)
                
                // Set up handler for packets read from the TUN interface
                func handlePackets(packets: [Data], protocols: [NSNumber]) {
                    // Iterate through each packet read, and write it to the UNIX socket
                    // for the Tinc Daemon to read
                    NSLog("Read %d packets from TUN...", packets.count)
                    for i in 0..<(packets.count) {
                        // Print out packet bytes for debugging purposes
                        let protocolString = (AF_INET == Int32(protocols[i])) ?
                                                "IPv4" :
                                                ((AF_INET6 == Int32(protocols[i])) ? "IPv6" : "Unknown")
                        let protocolCStr = strdup(protocolString)
                        NSLog("(%s) %d bytes", protocolCStr!, packets[i].count)

                        // Add Routing Info Header for Tinc
                        // Header Format: 12 zero bytes + Routing Code in Bytes 13-14
                        // Routing Code = 0x0800 for IPv4, 0x86DD for IPv6
                        var validPkt = true
                        var tincHdr: [UInt8] = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ]
                        if (AF_INET == Int32(protocols[i])) {
                            tincHdr.append(0x08)
                            tincHdr.append(0x00)
                        } else if (AF_INET6 == Int32(protocols[i])) {
                            tincHdr.append(0x86)
                            tincHdr.append(0xDD)
                        } else {
                            NSLog("Unknown IP Version, dropping packet!")
                            validPkt = false
                        }
                        var tincPkt = packets[i]
                        tincPkt.insert(contentsOf: tincHdr, at: 0)
                        
                        // Write Tinc Routing Header + Raw IP Packet to Write socket
                        if (validPkt) {
                            NSLog("Forwarding %d bytes to Tinc", packets[i].count)
                            let pktData = tincPkt as NSData
                            let writtenBytes = write(self.writeFd, pktData.bytes, pktData.length)
                            if (writtenBytes < pktData.length) {
                                NSLog("Write Socket write failure. Wrote only %d of %d bytes.", writtenBytes,
                                      pktData.length)
                            } else  if (-1 == writtenBytes) {
                                NSLog("Write Socket write failed with error: %s", strerror(errno))
                                let writeErr: Error? = NSError(domain: "Socket Write Failure",
                                                               code: 1005,
                                                               userInfo: nil) as Error?
                                completionHandler(writeErr)
                                return
                            }
                        }
                    }

                    // Read the next packet and repeat...
                    self.packetFlow.readPackets(completionHandler: handlePackets)
                }
                
                // Start reading packets from the TUN interface
                NSLog("Ready to receive packets from TUN")
                self.packetFlow.readPackets(completionHandler: handlePackets)
                
                // Begin event loop for receiving packets from Tinc
                var bkQueue: DispatchQueue?
                bkQueue = DispatchQueue(
                    label: "com.apple.queue",
                    qos: .background,
                    attributes: .concurrent,
                    autoreleaseFrequency: .inherit,
                    target: bkQueue
                )
                bkQueue?.async {
                    // TO DO: Write the handler for UDP packets coming from Tinc (write them to TUN interface)
                    
                    let bufSize = 1000
                    var readBuf: [ UInt8 ] = Array(repeating: 0, count: bufSize)
                    
                    NSLog("Ready to receive packets from Tinc")
                    while (true) {
                        let bytesRead = readBuf.withUnsafeBytes() { buf in
                            read(self.readFd,
                                 unsafeBitCast(buf.baseAddress!, to: UnsafeMutableRawPointer!.self),
                                 MemoryLayout<UInt8>.size * bufSize)
                        } // readBuf.withUnsafeBytes()...read(...)
                        
                        if (-1 == bytesRead) {
                            NSLog("Read Socket read failed with error: %s", strerror(errno))
                            let readReadErr: Error? = NSError(domain: "Read Socket Read Failure",
                                                              code: 1005,
                                                              userInfo: nil) as Error?
                            self.cancelTunnelWithError(readReadErr)
                            exit(0)
                        } else if (0 == bytesRead) {
                            NSLog("No bytes read from buffer")
                        } else {
                            // Validate and forward packet to Tinc
                            // Begin by validating packet length
                            // The packet must be at least 15 bytes long
                            // The first 14 bytes will contain the Tinc Routing Header
                            NSLog("Received packet from Tinc: %d bytes", bytesRead)
                            var pktError = false
                            var writePkts: [ Data ] = [ Data() ]
                            var writeProtocols: [ NSNumber ] = [ 0 ]
                            if (bytesRead < 15) {
                                NSLog("Packet too short, dropping packet")
                            } else {
                                // Skip the first 14 bytes of the packet that contain the Tinc Routing Header
                                // and forward the remaining (the IP packet) to the TUN interface
                                for bi in 14..<(bytesRead) {
                                    writePkts[0].append(readBuf[bi])
                                }
                                // Check bytes 13 and 14 for the IP type
                                // 0x0800 = IPv4, 0x86DD = IPv6 (this is the Tinc protocol)
                                if (0x08 == readBuf[12] && 0x00 == readBuf[13]) {
                                    writeProtocols[0] = NSNumber(integerLiteral: Int(AF_INET))
                                } else if (0x86 == readBuf[12] && 0xDD == readBuf[13]) {
                                    writeProtocols[0] = NSNumber(integerLiteral: Int(AF_INET6))
                                } else {
                                    NSLog("Unknown IP type, dropping packet")
                                    pktError = true
                                } // if...readBuf[12]... && readBuf[13]...
                                
                                if (!pktError) {
                                    // Write packet to TUN
                                    let protocolStr = (NSNumber(integerLiteral: Int(AF_INET)) ==
                                                        writeProtocols[0]) ? "IPv4" : "IPv6"
                                    let protocolCStr = strdup(protocolStr)
                                    NSLog("Forwarding %d bytes (%s) to TUN", bytesRead - 14,
                                          protocolCStr!)
                                    self.packetFlow.writePackets(writePkts, withProtocols: writeProtocols)
                                } // if !pktError
                            } // if bytesRead < 15
                        } // bytesRead validations
                        
                    } // while readPkts
                }   // bkQueue.async
                
                // Call completion handler to indicate VPN connection success
                completionHandler(nil)
                
                return
            } // if err
        }
        
    }
    
    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        // Close all the sockets and pipes opened during startTunnel()
        // and unlink all socket and pipe files so that they can be
        // created for the next VPN connection
        NSLog("Closing UML sockets and unlinking paths")
        if (nil != self.requestFd && self.requestFd > 0) {
            let reqCloseStat = close(self.requestFd)
            if (-1 == reqCloseStat) {
                NSLog("Request Socket close failed with error: %s", strerror(errno))
            }
            self.requestFd = nil
        }
        
        if (nil != self.writeFd && self.writeFd > 0) {
            let writeCloseStat = close(self.writeFd)
            if (-1 == writeCloseStat) {
                NSLog("Write Socket close failed with error: %s", strerror(errno))
            }
            self.writeFd = nil
        }
        
        // Temporary code to unlink Request and Write socket paths
        unlink(self.requestPathStr)
        unlink(self.writePathStr)
        
        if (nil != self.readFd && self.readFd > 0) {
            let readCloseStat = close(self.readFd)
            if (-1 == readCloseStat) {
                NSLog("Read Socket close failed with error: %s", strerror(errno))
            }
            self.readFd = nil
        }
        
        let readUnlinkStat = unlink(self.readPathStr)
        if (-1 == readUnlinkStat) {
            NSLog("Read Socket unlink failed with error: %s", strerror(errno))
        }

        NSLog("Closing named pipe and unlinking file")
        if (nil != self.pipeFd && self.pipeFd > 0) {
            let pipeCloseStat = close(self.pipeFd)
            if (-1 == pipeCloseStat) {
                NSLog("Pipe close failed with error: %s", strerror(errno))
            }
            self.pipeFd = nil
        } else {
            NSLog("No Named Pipe to close")
        }
        
        let pipeUnlinkStat = unlink(self.pipePathStr)
        if (-1 == pipeUnlinkStat) {
            NSLog("Pipe unlink failed with error: %s", strerror(errno))
        }

        completionHandler()
    }
    
}
