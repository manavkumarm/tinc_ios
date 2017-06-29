/*
 fake-if_ether.h -- Declarations for running Tinc daemon on iOS,
 required because the iPhone SDK does not include netinet/if_ether.h
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


#ifndef fake_if_ether_h
#define fake_if_ether_h

#include "fake-if_arp.h"

struct  ether_arp {
    struct  arphdr ea_hdr;  /* fixed-size header */
    u_char  arp_sha[ETHER_ADDR_LEN];        /* sender hardware address */
    u_char  arp_spa[4];     /* sender protocol address */
    u_char  arp_tha[ETHER_ADDR_LEN];        /* target hardware address */
    u_char  arp_tpa[4];     /* target protocol address */
};
#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op  ea_hdr.ar_op

#endif /* fake_if_ether_h */
