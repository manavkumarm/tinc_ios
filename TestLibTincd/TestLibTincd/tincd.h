/*
    tincd.h -- Declarations for tincd.c
    Copyright (C) 1998-2005 Ivo Timmermans
                  2000-2016 Guus Sliepen <guus@tinc-vpn.org>
                  2008      Max Rijevski <maksuf@gmail.com>
                  2009      Michael Tokarev <mjt@tls.msk.ru>
                  2010      Julien Muchembled <jm@jmuchemb.eu>
                  2010      Timothy Redaelli <timothy@redaelli.eu>
                  2017      Elear Solutions Tech. Pvt. Ltd. <mail@elear.solutions>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef _TINCD_H
#define _TINCD_H

// Implementing C++ compatability to facilitate invoking this daemon as a library from Xcode projects
// Xcode Objective-C projects must import this file - import "tincd.h" in Objective-C source files
// Xcode Swift projects must create a Swift bridging header and import it in the Swift source files
#ifdef __cplusplus
extern "C" {
#endif

// Main Library function to be used for invoking tinc as a library
// To activate this, compile with the -DLIBTINCD switch
#if defined(LIBTINCD)
int libtincd_main(int argc, char **argv);
#endif

void set_ios_log_cb(void (*cb)(const char *, void *), void *ctxt);
    
// C++ compatability for invoking this daemon as a library from Xcode projects
// This is the ending brace for the extern "C" block started above
#ifdef __cplusplus
}
#endif

#endif  // _TINCD_H
