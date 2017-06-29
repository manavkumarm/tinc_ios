//
//  ViewController.swift
//  TestLibTincd
//
//  Created by Manav Kumar Mehta on 6/3/17.
//  Copyright © 2017 Elear Solutions Tech. Pvt. Ltd. All rights reserved.
//

import UIKit
import Foundation
import NetworkExtension
import NotificationCenter

public func printConnectionStatus(stat: NEVPNStatus) -> String {
    switch stat {
        case NEVPNStatus.connected:
            return "connected"
        
        case NEVPNStatus.connecting:
            return "connecting"
        
        case NEVPNStatus.disconnected:
            return "disconnected"
        
        case NEVPNStatus.disconnecting:
            return "disconnecting"
        
        case NEVPNStatus.invalid:
            return "invalid"
        
        case NEVPNStatus.reasserting:
            return "reasserting"
    }
}


class ViewController: UIViewController, UITextViewDelegate {
    @IBOutlet weak var textviewLog: UITextView!

    let logTincMessages = false     // Set this to true to see Tinc log messages in the debug log
    
    var bkQueue: DispatchQueue?
    var vpnMgr: NETunnelProviderManager!
    
    var textViewText: String!
    
    var pipeFd: Int32!
    var pipePathStr: UnsafeMutablePointer<Int8>!

    override func viewDidLoad() {
        super.viewDidLoad()
        
        self.textviewLog.delegate = self
        
        // Do any additional setup after loading the view, typically from a nib.
        /* Starting a background thread here */
        bkQueue = DispatchQueue(
                    label: "com.apple.queue",
                    qos: .background,
                    attributes: .concurrent,
                    autoreleaseFrequency: .inherit,
                    target: bkQueue
        )
        bkQueue?.async {
            let pipeFile = "tincd.pipe"
            self.pipePathStr = strdup((FileManager.default.containerURL(
                forSecurityApplicationGroupIdentifier: "group.solutions.elear.Tincd")?.path)! +
                "/" + pipeFile)

            func connectVPN() {
                // Set up Observer for VPN Status changes
                print("Registering Observer for VPN status")
                NotificationCenter.default.addObserver(
                    forName: NSNotification.Name.NEVPNStatusDidChange,
                    object: self.vpnMgr.connection,
                    queue: OperationQueue.main,
                    using: { notification in
                        print("VPN Status: \(printConnectionStatus(stat: self.vpnMgr.connection.status))")
                    }
                )
                
                // Initiate the VPN startup process
                do {
                    print("Starting VPN")
                    try self.vpnMgr.connection.startVPNTunnel()
                } catch {
                    print("Failed to start VPN: \(error.localizedDescription)")
                    exit(0)
                }

                // Wait for Named Pipe to be created then open the named pipe to communicate 
                // with the VPN extension
                print("Waiting for Tinc to create named pipe")
                let pipeTimeout = 10        // Exit if pipe is not created within this duration (in secs)
                let pipeWait = 0.5          // Sleep interval between re-tries (in secs)
                var pipeElapsed = 0.0
                var pipeDelay = timespec()
                pipeDelay.tv_nsec = Int(pipeWait * Double(1000000000))
                var pipeFileInfo = stat()
                while (-1 == stat(self.pipePathStr!, &pipeFileInfo)) {
                    if (pipeElapsed == Double(pipeTimeout)) {
                        print("Timed out waiting for named pipe from Tinc")
                        exit(0)
                    }
                    nanosleep(&pipeDelay, nil)
                    pipeElapsed = pipeElapsed + pipeWait
                }
                print("Opening named pipe")
                self.pipeFd = open(self.pipePathStr!, O_RDONLY)
                if (-1 == self.pipeFd) {
                    print("Pipe open failed due to error: \(String(cString: strerror(errno)!))")
                    exit(0)
                }
                
                // Begin event loop to start listening for messages on the named pipe
                print("Starting to monitor named pipe for log messages from Tinc")
                var bkPipeQueue: DispatchQueue?
                bkPipeQueue = DispatchQueue(
                    label: "com.apple.queue",
                    qos: .background,
                    attributes: .concurrent,
                    autoreleaseFrequency: .inherit,
                    target: bkPipeQueue
                )
                bkPipeQueue?.async {
                    while (true) {
                        let bufSize = 255
                        var message: (
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8, Int8,
                            Int8, Int8, Int8, Int8, Int8, Int8, Int8
                            ) = (
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
                                0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0
                        )
                        let pipeBytesRead = withUnsafeBytes(of: &message) { msgPtr in
                            read(self.pipeFd!,
                                 unsafeBitCast(msgPtr.baseAddress!, to: UnsafeMutableRawPointer!.self),
                                 MemoryLayout<Int8>.size * bufSize)
                        }
                        
                        if (-1 == pipeBytesRead) {
                            print("Pipe read failed with error: \(String(cString: strerror(errno)!))")
                            exit(0)
                        } else if (0 == pipeBytesRead) {
                            print("Pipe closed. Exiting.")
                            exit(0)
                        } else {
                            var msgCStr = withUnsafeMutablePointer(to: &message) { tempMsgPtr in
                                tempMsgPtr.withMemoryRebound(to: Int8.self,
                                                             capacity: 1) { msgPtr in
                                    unsafeBitCast(msgPtr, to: UnsafeMutablePointer<Int8>!.self)
                                }
                            }
                            
                            // Log all the messages read from the pipe
                            // There can be null-terminating characters in the middle of the
                            // character sequence read from the pipe
                            // Also, the character sequence may be incomplete and therefore may not
                            // have a null terminating character
                            // Processing steps:
                            // 1: Add a null terminating character at the end of the sequence read
                            // 2: Iterate through null-terminated strings till there are none
                            // left to log
                            if (pipeBytesRead < bufSize) {
                                memset(msgCStr! + pipeBytesRead, 0, 1)
                            } else {
                                memset(msgCStr! + bufSize - 1, 0, 1)
                            }
                            var loggingDone = false
                            var charsToWrite = Int(pipeBytesRead / MemoryLayout<Int8>.size)
                            while (!loggingDone) {
                                if (self.logTincMessages) {
                                    print("Tinc Log Message: \(String(cString: msgCStr!))")
                                } // if self.logTincMessages
                                let dateFormatter = DateFormatter()
                                // Time format for log: hours, minutes, seconds
                                dateFormatter.setLocalizedDateFormatFromTemplate("HH:mm:ss")
                                let logTime = strdup(dateFormatter.string(from: Date()) + " ")
                                self.updateLog(txt: logTime)     // Prepend time before log message
                                self.updateLog(txt: msgCStr)
                                let charsWritten = Int(strlen(msgCStr)) + 1
                                if (charsWritten == charsToWrite) {
                                    loggingDone = true
                                } else {
                                    msgCStr = msgCStr! + charsWritten
                                    charsToWrite = charsToWrite - charsWritten
                                }
                            }
                            memset(&message, 0, MemoryLayout<Int8>.size * 256)
                        }
                    }
                }
                
            }   // connectVPN()
            
            // Create VPN Profile and save to iPhone device preferences
            // VPN Profile will be visible under Settings > General > VPN
            print("Examining VPN profiles...")
            NETunnelProviderManager.loadAllFromPreferences() {(
                mgrs: [NETunnelProviderManager]?,
                err: Error?
                ) in
                
                // Check if preference load was successful
                if (nil != err) {
                    print("Failed to load VPN Profile: \(err.debugDescription)")
                    return
                }
                
                // Successful profile load:
                // If there is more than one profile, delete all profiles so a new profile can be created
                var removeError = false
                if (nil != mgrs && (mgrs!.count) > 1) {
                    print("More than one VPN profile found. Setting up new VPN profile.")
                    for mgr in mgrs! {
                        mgr.removeFromPreferences() { err in
                            
                            if (nil != err) {
                                removeError = true
                                print("Failed to remove profile '\(String(describing: mgr.localizedDescription))' due to error: \(err!.localizedDescription)")
                            }
                        } // removeFromPreferences()
                    } // for
                } // if mgrs
                
                // If there is exactly one existing profile, set it as the Manager instance,
                // otherwise create a new instance
                if (nil != mgrs && 1 == (mgrs!.count)) {
                    self.vpnMgr = mgrs![0]
                } else {
                    print("Setting up new VPN profile.")
                    self.vpnMgr = NETunnelProviderManager()
                } // if 1 == (mgrs!.count)
                
                // If existing configs were removed successfully or there were 0 or 1 profiles, 
                // continue processing...
                if (!removeError) {
                    // Load the latest profiles
                    self.vpnMgr.loadFromPreferences() { err in
                        
                        if (nil != err) {
                            print("Failed to load latest VPN Profile: \(err!.localizedDescription)")
                            return
                        }
                        
                        // Successful load of latest profiles:
                        // If there were 0 or > 1 profiles, create a new profile and use it to connect
                        // otherwise connect using the latest profile
                        if (nil == mgrs || 0 == mgrs!.count || (nil != mgrs && (mgrs!.count) > 1)) {
                            let vpnProtocol = NETunnelProviderProtocol()
                            vpnProtocol.providerBundleIdentifier = "solutions.elear.TestLibTincd.TincVPNTunnelProvider"
                            vpnProtocol.serverAddress = "127.0.0.1"
                            vpnProtocol.providerConfiguration = nil
                            
                            self.vpnMgr.protocolConfiguration = vpnProtocol
                            self.vpnMgr.localizedDescription = "Tinc VPN"
                            self.vpnMgr.isEnabled = true
                            self.vpnMgr.saveToPreferences() { err in
                                
                                if (nil != err) {
                                    print("Failed to save VPN Profile: \(err!.localizedDescription)")
                                    return
                                }
                                
                                // Successful save: re-load the latest profile after save
                                self.vpnMgr.loadFromPreferences() { err in
                                    
                                    if (nil != err) {
                                        print("Failed from re-load VPN profile after save: \(err!.localizedDescription)")
                                        return
                                    }
                                    // Re-load successful: Connect to VPN
                                    connectVPN()
                                    
                                } // loadFromPreferences() -- call # 2 after first save
                            } // saveToPreferences()
                        } else {
                            // Exactly one profile exists -- use it to connect to the VPN
                            connectVPN()
                        }  // if mgrs!...else
                    }  // loadFromPreferences -- call # 1
                } // if !removeError
                
            } // loadAllFromPreferences()

        }
        
        return
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    @objc func updateTextView(txt: String) {
        let newText: String = self.textviewLog.text + txt
        self.textviewLog.text = newText
        return
    }
    
    func updateLog(txt: UnsafePointer<Int8>?) -> Void {
        performSelector(
            onMainThread: #selector(ViewController.updateTextView(txt:)),
            with: String(cString: txt!),
            waitUntilDone: false
        )
        return
    }
    
}

