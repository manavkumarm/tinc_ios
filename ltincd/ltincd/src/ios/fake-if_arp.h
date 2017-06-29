/*
 fake-if_arp.h -- Declarations for running Tinc daemon on iOS,
 required because the iPhone SDK does not include net/if_arp.h
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

#ifndef fake_if_arp_h
#define fake_if_arp_h

struct  arphdr {
    u_short ar_hrd;         /* format of hardware address */
#define ARPHRD_ETHER    1       /* ethernet hardware format */
#define ARPHRD_IEEE802  6       /* token-ring hardware format */
#define ARPHRD_FRELAY   15      /* frame relay hardware format */
#define ARPHRD_IEEE1394 24      /* IEEE1394 hardware address */
#define ARPHRD_IEEE1394_EUI64 27 /* IEEE1394 EUI-64 */
    u_short ar_pro;         /* format of protocol address */
    u_char  ar_hln;         /* length of hardware address */
    u_char  ar_pln;         /* length of protocol address */
    u_short ar_op;          /* one of: */
#define ARPOP_REQUEST   1       /* request to resolve address */
#define ARPOP_REPLY     2       /* response to previous request */
#define ARPOP_REVREQUEST 3      /* request protocol address given hardware */
#define ARPOP_REVREPLY  4       /* response giving protocol address */
#define ARPOP_INVREQUEST 8      /* request to identify peer */
#define ARPOP_INVREPLY  9       /* response identifying peer */
    /*
     * The remaining fields are variable in size,
     * according to the sizes above.
     */
#ifdef COMMENT_ONLY
    u_char  ar_sha[];       /* sender hardware address */
    u_char  ar_spa[];       /* sender protocol address */
    u_char  ar_tha[];       /* target hardware address */
    u_char  ar_tpa[];       /* target protocol address */
#endif
};


#endif /* fake_if_arp_h */
