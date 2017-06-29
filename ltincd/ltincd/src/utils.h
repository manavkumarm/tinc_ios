/*
    utils.h -- header file for utils.c
    Copyright (C) 1999-2005 Ivo Timmermans
                  2000-2014 Guus Sliepen <guus@tinc-vpn.org>
                  2017-2018 Manav Kumar Mehta <manavkumarm@yahoo.com>

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

#ifndef __TINC_UTILS_H__
#define __TINC_UTILS_H__

/********* BEGIN CHANGE: Manav Kumar Mehta, Jun 2017 *********/
// Header files required for declaring utility functions for printing out the
// hardcoded configuration for debugging
#include "avl_tree.h"
#include "conf.h"
/********* END CHANGE: Manav Kumar Mehta, Jun 2017 *********/

extern bool hex2bin(char *src, char *dst, int length);
extern void bin2hex(char *src, char *dst, int length);

#ifdef HAVE_MINGW
extern const char *winerror(int);
#define strerror(x) ((x)>0?strerror(x):winerror(GetLastError()))
#define sockerrno WSAGetLastError()
#define sockstrerror(x) winerror(x)
#define sockwouldblock(x) ((x) == WSAEWOULDBLOCK || (x) == WSAEINTR)
#define sockmsgsize(x) ((x) == WSAEMSGSIZE)
#define sockinprogress(x) ((x) == WSAEINPROGRESS || (x) == WSAEWOULDBLOCK)
#else
#define sockerrno errno
#define sockstrerror(x) strerror(x)
#define sockwouldblock(x) ((x) == EWOULDBLOCK || (x) == EINTR)
#define sockmsgsize(x) ((x) == EMSGSIZE)
#define sockinprogress(x) ((x) == EINPROGRESS)
#endif

extern unsigned int bitfield_to_int(const void *bitfield, size_t size);

int memcmp_constant_time (const void *a, const void *b, size_t size);

/********* BEGIN CHANGE: Manav Kumar Mehta, Jun 2017 *********/
// Declaration for  utility function for printing out the hardcoded configuration for debugging
void dump_config(avl_tree_t *ctree, const char *cname);
/********* END CHANGE: Manav Kumar Mehta, Jun 2017 *********/

#endif							/* __TINC_UTILS_H__ */