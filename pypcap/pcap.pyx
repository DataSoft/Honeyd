#
# pcap.pyx
#
# $Id: pcap.pyx,v 1.1.1.1 2005/10/29 18:25:03 provos Exp $

"""packet capture library

This module provides a high level interface to packet capture systems.
All packets on the network, even those destined for other hosts, are
accessible through this mechanism.
"""

__author__ = 'Dug Song <dugsong@monkey.org>'
__copyright__ = 'Copyright (c) 2004 Dug Song'
__license__ = 'BSD license'
__url__ = 'http://monkey.org/~dugsong/pypcap/'
__version__ = '1.1'

import sys

cdef extern from "Python.h":
    object PyBuffer_FromMemory(char *s, int len)
    int    PyGILState_Ensure()
    void   PyGILState_Release(int gil)
    void   Py_BEGIN_ALLOW_THREADS()
    void   Py_END_ALLOW_THREADS()
    
cdef extern from "pcap.h":
    struct bpf_insn:
        int __xxx
    struct bpf_program:
        bpf_insn *bf_insns
    struct bpf_timeval:
        unsigned int tv_sec
        unsigned int tv_usec
    struct pcap_stat:
        unsigned int ps_recv
        unsigned int ps_drop
        unsigned int ps_ifdrop
    struct pcap_pkthdr:
        bpf_timeval ts
        unsigned int caplen
    ctypedef struct pcap_t:
        int __xxx

ctypedef void (*pcap_handler)(void *arg, pcap_pkthdr *hdr, char *pkt)

cdef extern from "pcap.h":
    pcap_t *pcap_open_live(char *device, int snaplen, int promisc,
                           int to_ms, char *errbuf)
    pcap_t *pcap_open_offline(char *fname, char *errbuf)
    int     pcap_compile(pcap_t *p, bpf_program *fp, char *str, int optimize,
                         unsigned int netmask)
    int     pcap_setfilter(pcap_t *p, bpf_program *fp)
    void    pcap_freecode(bpf_program *fp)
    int     pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback,
                          unsigned char *arg)
    unsigned char *pcap_next(pcap_t *p, pcap_pkthdr *hdr)
    int     pcap_datalink(pcap_t *p)
    int     pcap_snapshot(pcap_t *p)
    int     pcap_stats(pcap_t *p, pcap_stat *ps)
    char   *pcap_geterr(pcap_t *p)
    void    pcap_close(pcap_t *p)
    int     bpf_filter(bpf_insn *insns, char *buf, int len, int caplen)

cdef extern from "pcap_ex.h":
    # XXX - hrr, sync with libdnet and libevent
    int     pcap_ex_immediate(pcap_t *p)
    char   *pcap_ex_name(char *name)
    char   *pcap_ex_lookupdev(char *ebuf)
    int     pcap_ex_fileno(pcap_t *p)
    void    pcap_ex_setup(pcap_t *p)
    void    pcap_ex_setnonblock(pcap_t *p, int nonblock, char *ebuf)
    int     pcap_ex_getnonblock(pcap_t *p, char *ebuf)
    int     pcap_ex_next(pcap_t *p, pcap_pkthdr **hdr, char **pkt)
    int     pcap_ex_compile_nopcap(int snaplen, int dlt,
                                   bpf_program *fp, char *str,
                                   int optimize, unsigned int netmask)

cdef extern from *:
    char *strdup(char *src)
    void  free(void *ptr)
    
cdef struct pcap_handler_ctx:
    void *callback
    void *args
    int   got_exc

cdef void __pcap_handler(void *arg, pcap_pkthdr *hdr, char *pkt):
    cdef pcap_handler_ctx *ctx
    cdef int gil
    ctx = <pcap_handler_ctx *>arg
    gil = PyGILState_Ensure()
    try:
        (<object>ctx.callback)(hdr.ts.tv_sec + (hdr.ts.tv_usec/1000000.0),
                               PyBuffer_FromMemory(pkt, hdr.caplen),
                               *(<object>ctx.args))
    except:
        ctx.got_exc = 1
    PyGILState_Release(gil)

DLT_NULL =	0
DLT_EN10MB =	1
DLT_EN3MB =	2
DLT_AX25 =	3
DLT_PRONET =	4
DLT_CHAOS =	5
DLT_IEEE802 =	6
DLT_ARCNET =	7
DLT_SLIP =	8
DLT_PPP =	9
DLT_FDDI =	10
# XXX - Linux
DLT_LINUX_SLL =	113
# XXX - OpenBSD
DLT_PFLOG =	117
DLT_PFSYNC =	18
if sys.platform.find('openbsd') != -1:
    DLT_LOOP =		12
    DLT_RAW =		14
else:
    DLT_LOOP =		108
    DLT_RAW =		12

dltoff = { DLT_NULL:4, DLT_EN10MB:14, DLT_IEEE802:22, DLT_ARCNET:6,
          DLT_SLIP:16, DLT_PPP:4, DLT_FDDI:21, DLT_PFLOG:48, DLT_PFSYNC:4,
          DLT_LOOP:4, DLT_RAW:0, DLT_LINUX_SLL:16 }

cdef class bpf:
    """bpf(filter, dlt=DLT_RAW) -> BPF filter object"""
    cdef bpf_program fcode
    def __init__(self, char *filter, dlt=DLT_RAW):
        if pcap_ex_compile_nopcap(65535, dlt, &self.fcode, filter, 1, 0) < 0:
            raise IOError, 'bad filter'
    def filter(self, buf):
        """Return boolean match for buf against our filter."""
        cdef int n
        n = len(buf)
        if bpf_filter(self.fcode.bf_insns, buf, n, n) == 0:
            return False
        return True
    def __dealloc__(self):
        pcap_freecode(&self.fcode)
            
cdef class pcap:
    """pcap(name=None, snaplen=65535, promisc=True, immediate=False) -> packet capture object
    
    Open a handle to a packet capture descriptor.
    
    Keyword arguments:
    name      -- name of a network interface or dumpfile to open,
                 or None to open the first available up interface
    snaplen   -- maximum number of bytes to capture for each packet
    promisc   -- boolean to specify promiscuous mode sniffing
    immediate -- disable buffering, if possible
    """
    cdef pcap_t *__pcap
    cdef char *__name
    cdef char *__filter
    cdef char __ebuf[256]
    cdef int __dloff
    
    def __init__(self, name=None, snaplen=65535, promisc=True,
                 timeout_ms=500, immediate=False):
        global dltoff
        cdef char *p
        
        if not name:
            p = pcap_ex_lookupdev(self.__ebuf)
            if p == NULL:
                raise OSError, self.__ebuf
        else:
            p = name
        
        self.__pcap = pcap_open_offline(p, self.__ebuf)
        if not self.__pcap:
            self.__pcap = pcap_open_live(pcap_ex_name(p), snaplen, promisc,
                                         timeout_ms, self.__ebuf)
        if not self.__pcap:
            raise OSError, self.__ebuf
        
        self.__name = strdup(p)
        self.__filter = strdup("")
        try: self.__dloff = dltoff[pcap_datalink(self.__pcap)]
        except KeyError: pass
        if immediate and pcap_ex_immediate(self.__pcap) < 0:
            raise OSError, "couldn't set BPF immediate mode"
    
    property name:
        """Network interface or dumpfile name."""
        def __get__(self):
            return self.__name

    property snaplen:
        """Maximum number of bytes to capture for each packet."""
        def __get__(self):
            return pcap_snapshot(self.__pcap)
        
    property dloff:
        """Datalink offset (length of layer-2 frame header)."""
        def __get__(self):
            return self.__dloff

    property filter:
        """Current packet capture filter."""
        def __get__(self):
            return self.__filter
    
    property fd:
        """File descriptor (or Win32 HANDLE) for capture handle."""
        def __get__(self):
            return pcap_ex_fileno(self.__pcap)
        
    def fileno(self):
        """Return file descriptor (or Win32 HANDLE) for capture handle."""
        return pcap_ex_fileno(self.__pcap)
    
    def setfilter(self, value, optimize=1):
        """Set BPF-format packet capture filter."""
        cdef bpf_program fcode
        free(self.__filter)
        self.__filter = strdup(value)
        if pcap_compile(self.__pcap, &fcode, self.__filter, optimize, 0) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        if pcap_setfilter(self.__pcap, &fcode) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        pcap_freecode(&fcode)

    def setnonblock(self, nonblock=True):
        """Set non-blocking capture mode."""
        pcap_ex_setnonblock(self.__pcap, nonblock, self.__ebuf)
    
    def getnonblock(self):
        """Return non-blocking capture mode as boolean."""
        ret = pcap_ex_getnonblock(self.__pcap, self.__ebuf)
        if ret < 0:
            raise OSError, self.__ebuf
        elif ret:
            return True
        return False
    
    def datalink(self):
        """Return datalink type (DLT_* values)."""
        return pcap_datalink(self.__pcap)
    
    def next(self):
        """Return the next (timestamp, packet) tuple, or None on error."""
        cdef pcap_pkthdr hdr
        cdef char *pkt
        pkt = <char *>pcap_next(self.__pcap, &hdr)
        if not pkt:
            return None
        return (hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                PyBuffer_FromMemory(pkt, hdr.caplen))

    def __add_pkts(self, ts, pkt, pkts):
        pkts.append((ts, pkt))
    
    def readpkts(self):
        """Return a list of (timestamp, packet) tuples received in one buffer."""
        pkts = []
        self.dispatch(-1, self.__add_pkts, pkts)
        return pkts
    
    def dispatch(self, cnt, callback, *args):
        """Collect and process packets with a user callback,
        return the number of packets processed, or 0 for a savefile.
        
        Arguments:
        
        cnt      -- number of packets to process;
                    or 0 to process all packets until an error occurs,
                    EOF is reached, or the read times out;
                    or -1 to process all packets received in one buffer
        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pcap_handler_ctx ctx
        cdef int n

        ctx.callback = <void *>callback
        ctx.args = <void *>args
        ctx.got_exc = 0
        n = pcap_dispatch(self.__pcap, cnt, __pcap_handler,
                          <unsigned char *>&ctx)
        if ctx.got_exc:
            exc = sys.exc_info()
            raise exc[0], exc[1], exc[2]
        return n

    def loop(self, callback, *args):
        """Loop forever, processing packets with a user callback.
        The loop can be exited with an exception, including KeyboardInterrupt.
        
        Arguments:

        callback -- function with (timestamp, pkt, *args) prototype
        *args    -- optional arguments passed to callback on execution
        """
        cdef pcap_pkthdr *hdr
        cdef char *pkt
        cdef int n
        pcap_ex_setup(self.__pcap)
        while 1:
            Py_BEGIN_ALLOW_THREADS
            n = pcap_ex_next(self.__pcap, &hdr, &pkt)
            Py_END_ALLOW_THREADS
            if n == 1:
                callback(hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                         PyBuffer_FromMemory(pkt, hdr.caplen), *args)
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                break
    
    def geterr(self):
        """Return the last error message associated with this handle."""
        return pcap_geterr(self.__pcap)
    
    def stats(self):
        """Return a 3-tuple of the total number of packets received,
        dropped, and dropped by the interface."""
        cdef pcap_stat pstat
        if pcap_stats(self.__pcap, &pstat) < 0:
            raise OSError, pcap_geterr(self.__pcap)
        return (pstat.ps_recv, pstat.ps_drop, pstat.ps_ifdrop)

    def __iter__(self):
        pcap_ex_setup(self.__pcap)
        return self

    def __next__(self):
        cdef pcap_pkthdr *hdr
        cdef char *pkt
        cdef int n
        while 1:
            Py_BEGIN_ALLOW_THREADS
            n = pcap_ex_next(self.__pcap, &hdr, &pkt)
            Py_END_ALLOW_THREADS
            if n == 1:
                return (hdr.ts.tv_sec + (hdr.ts.tv_usec / 1000000.0),
                        PyBuffer_FromMemory(pkt, hdr.caplen))
            elif n == -1:
                raise KeyboardInterrupt
            elif n == -2:
                raise StopIteration
    
    def __dealloc__(self):
        if self.__name:
            free(self.__name)
        if self.__filter:
            free(self.__filter)
        if self.__pcap:
            pcap_close(self.__pcap)

def ex_name(char *foo):
    return pcap_ex_name(foo)

def lookupdev():
    """Return the name of a network device suitable for sniffing."""
    cdef char *p, ebuf[256]
    p = pcap_ex_lookupdev(ebuf)
    if p == NULL:
        raise OSError, ebuf
    return p

