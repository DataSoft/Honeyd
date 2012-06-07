/*
 * Copyright (c) 2004 Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/types.h>
#include <sys/param.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/tree.h>

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <ctype.h>

#include <dnet.h>

#include "ethernet.h"

struct etherindex {
	SPLAY_ENTRY(etherindex) node;

	char *index_word;

	struct ethernetcode **list;
	size_t list_size;
	size_t list_mem;
};

struct ethernetcode {
	uint32_t prefix;
	char *vendor;
	int count;
};

static SPLAY_HEAD(ethertree, etherindex) etherroot;

static int
compare(struct etherindex *a, struct etherindex *b)
{
	return (strcmp(a->index_word, b->index_word));
}

SPLAY_PROTOTYPE(ethertree, etherindex, node, compare);

SPLAY_GENERATE(ethertree, etherindex, node, compare);

/*
 * These codes have been obtained from
 *
 *   http://www.cavebear.com/CaveBear/Ethernet/vendor.html
 *
 * and other random sources on the Internet.
 */



static struct ethernetcode codes[] = {
{0x000000, "Xerox"}
{0x000001, "Xerox"}
{0x000002, "Xerox"}
{0x000003, "Xerox"}
{0x000004, "Xerox"}
{0x000005, "Xerox"}
{0x000006, "Xerox"}
{0x000007, "Xerox"}
{0x000008, "Xerox"}
{0x000009, "Xerox"}
{0x00000a, "Omron Tateisi Electronics CO."}
{0x00000b, "Matrix"}
{0x00000c, "Cisco Systems"}
{0x00000d, "Fibronics"}
{0x00000e, "Fujitsu Limited"}
{0x00000f, "NEXT"}
{0x000010, "Sytek"}
{0x000011, "Normerel Systemes"}
{0x000012, "Information Technology Limited"}
{0x000013, "Camex"}
{0x000014, "Netronix"}
{0x000015, "Datapoint"}
{0x000016, "DU Pont Pixel Systems"}
{0x000017, "Tekelec"}
{0x000018, "Webster Computer"}
{0x000019, "Applied Dynamics International"}
{0x00001a, "Advanced Micro Devices"}
{0x00001b, "Novell"}
{0x00001c, "Bell Technologies"}
{0x00001d, "Cabletron Systems"}
{0x00001e, "Telsist Industria Electronica"}
{0x00001f, "Telco Systems"}
{0x000020, "Dataindustrier Diab AB"}
{0x000021, "Sureman COMP. & Commun."}
{0x000022, "Visual Technology"}
{0x000023, "ABB Industrial Systems AB"}
{0x000024, "Connect AS"}
{0x000025, "Ramtek"}
{0x000026, "Sha-ken CO."}
{0x000027, "Japan Radio Company"}
{0x000028, "Prodigy Systems"}
{0x000029, "IMC Networks"}
{0x00002a, "TRW - Sedd/inp"}
{0x00002b, "Crisp Automation"}
{0x00002c, "Autotote Limited"}
{0x00002d, "Chromatics"}
{0x00002e, "Societe Evira"}
{0x00002f, "Timeplex"}
{0x000030, "VG Laboratory Systems"}
{0x000031, "Qpsx Communications"}
{0x000032, "Marconi plc"}
{0x000033, "Egan Machinery Company"}
{0x000034, "Network Resources"}
{0x000035, "Spectragraphics"}
{0x000036, "Atari"}
{0x000037, "Oxford Metrics Limited"}
{0x000038, "CSS Labs"}
{0x000039, "Toshiba"}
{0x00003a, "Chyron"}
{0x00003b, "i Controls"}
{0x00003c, "Auspex Systems"}
{0x00003d, "Unisys"}
{0x00003e, "Simpact"}
{0x00003f, "Syntrex"}
{0x000040, "Applicon"}
{0x000041, "ICE"}
{0x000042, "Metier Management Systems"}
{0x000043, "Micro Technology"}
{0x000044, "Castelle"}
{0x000045, "Ford Aerospace & COMM."}
{0x000046, "Olivetti North America"}
{0x000047, "Nicolet Instruments"}
{0x000048, "Seiko Epson"}
{0x000049, "Apricot Computers"}
{0x00004a, "ADC Codenoll Technology"}
{0x00004b, "ICL Data OY"}
{0x00004c, "NEC"}
{0x00004d, "DCI"}
{0x00004e, "Ampex"}
{0x00004f, "Logicraft"}
{0x000050, "Radisys"}
{0x000051, "HOB Electronic Gmbh & CO. KG"}
{0x000052, "Intrusion.com"}
{0x000053, "Compucorp"}
{0x000054, "Modicon"}
{0x000055, "Commissariat A L`energie ATOM."}
{0x000056, "DR. B. Struck"}
{0x000057, "Scitex"}
{0x000058, "Racore Computer Products"}
{0x000059, "Hellige Gmbh"}
{0x00005a, "SysKonnect GmbH"}
{0x00005b, "Eltec Elektronik AG"}
{0x00005c, "Telematics International"}
{0x00005d, "CS Telecom"}
{0x00005e, "USC Information Sciences Inst"}
{0x00005f, "Sumitomo Electric IND."}
{0x000060, "Kontron Elektronik Gmbh"}
{0x000061, "Gateway Communications"}
{0x000062, "Bull HN Information Systems"}
{0x000063, "Barco Control Rooms Gmbh"}
{0x000064, "Yokogawa Digital Computer"}
{0x000065, "Network General"}
{0x000066, "Talaris Systems"}
{0x000067, "Soft * RITE"}
{0x000068, "Rosemount Controls"}
{0x000069, "Concord Communications"}
{0x00006a, "Computer Consoles"}
{0x00006b, "Silicon Graphics/mips"}
{0x00006c, "Private"}
{0x00006d, "Cray Communications"}
{0x00006e, "Artisoft"}
{0x00006f, "Madge"}
{0x000070, "HCL Limited"}
{0x000071, "Adra Systems"}
{0x000072, "Miniware Technology"}
{0x000073, "Siecor"}
{0x000074, "Ricoh Company"}
{0x000075, "Nortel Networks"}
{0x000076, "Abekas Video System"}
{0x000077, "Interphase"}
{0x000078, "Labtam Limited"}
{0x000079, "Networth Incorporated"}
{0x00007a, "Dana Computer"}
{0x00007b, "Research Machines"}
{0x00007c, "Ampere Incorporated"}
{0x00007d, "Oracle"}
{0x00007e, "Clustrix"}
{0x00007f, "Linotype-hell AG"}
{0x000080, "Cray Communications A/S"}
{0x000081, "BAY Networks"}
{0x000082, "Lectra Systemes SA"}
{0x000083, "Tadpole Technology PLC"}
{0x000084, "Supernet"}
{0x000085, "Canon"}
{0x000086, "Megahertz"}
{0x000087, "Hitachi"}
{0x000088, "Brocade Communications Systems"}
{0x000089, "Cayman Systems"}
{0x00008a, "Datahouse Information Systems"}
{0x00008b, "Infotron"}
{0x00008c, "Alloy Computer Products (Australia)"}
{0x00008d, "Cryptek"}
{0x00008e, "Solbourne Computer"}
{0x00008f, "Raytheon"}
{0x000090, "Microcom"}
{0x000091, "Anritsu"}
{0x000092, "Cogent Data Technologies"}
{0x000093, "Proteon"}
{0x000094, "Asante Technologies"}
{0x000095, "Sony Tektronix"}
{0x000096, "Marconi Electronics"}
{0x000097, "EMC"}
{0x000098, "Crosscomm"}
{0x000099, "MTX"}
{0x00009a, "RC Computer A/S"}
{0x00009b, "Information International"}
{0x00009c, "Rolm Mil-spec Computers"}
{0x00009d, "Locus Computing"}
{0x00009e, "Marli S.A."}
{0x00009f, "Ameristar Technologies"}
{0x0000a0, "Sanyo Electric Co."}
{0x0000a1, "Marquette Electric CO."}
{0x0000a2, "BAY Networks"}
{0x0000a3, "Network Application Technology"}
{0x0000a4, "Acorn Computers Limited"}
{0x0000a5, "Compatible Systems"}
{0x0000a6, "Network General"}
{0x0000a7, "Network Computing Devices"}
{0x0000a8, "Stratus Computer"}
{0x0000a9, "Network Systems"}
{0x0000aa, "Xerox"}
{0x0000ab, "Logic Modeling"}
{0x0000ac, "Conware Computer Consulting"}
{0x0000ad, "Bruker Instruments"}
{0x0000ae, "Dassault Electronique"}
{0x0000af, "Nuclear Data Instrumentation"}
{0x0000b0, "Rnd-rad Network Devices"}
{0x0000b1, "Alpha Microsystems"}
{0x0000b2, "Televideo Systems"}
{0x0000b3, "Cimlinc Incorporated"}
{0x0000b4, "Edimax Computer Company"}
{0x0000b5, "Datability Software SYS."}
{0x0000b6, "Micro-matic Research"}
{0x0000b7, "Dove Computer"}
{0x0000b8, "Seikosha CO."}
{0x0000b9, "Mcdonnell Douglas Computer SYS"}
{0x0000ba, "SIIG"}
{0x0000bb, "Tri-data"}
{0x0000bc, "Rockwell Automation"}
{0x0000bd, "Mitsubishi Cable Company"}
{0x0000be, "THE NTI Group"}
{0x0000bf, "Symmetric Computer Systems"}
{0x0000c0, "Western Digital"}
{0x0000c1, "Madge"}
{0x0000c2, "Information Presentation TECH."}
{0x0000c3, "Harris Computer SYS DIV"}
{0x0000c4, "Waters DIV. OF Millipore"}
{0x0000c5, "Farallon Computing/netopia"}
{0x0000c6, "EON Systems"}
{0x0000c7, "Arix"}
{0x0000c8, "Altos Computer Systems"}
{0x0000c9, "Emulex"}
{0x0000ca, "Arris International"}
{0x0000cb, "Compu-shack Electronic Gmbh"}
{0x0000cc, "Densan CO."}
{0x0000cd, "Allied Telesis Labs"}
{0x0000ce, "Megadata"}
{0x0000cf, "Hayes Microcomputer Products"}
{0x0000d0, "Develcon Electronics"}
{0x0000d1, "Adaptec Incorporated"}
{0x0000d2, "SBE"}
{0x0000d3, "Wang Laboratories"}
{0x0000d4, "Pure Data"}
{0x0000d5, "Micrognosis International"}
{0x0000d6, "Punch Line Holding"}
{0x0000d7, "Dartmouth College"}
{0x0000d8, "Novell"}
{0x0000d9, "Nippon Telegraph & Telephone"}
{0x0000da, "Atex"}
{0x0000db, "British Telecommunications PLC"}
{0x0000dc, "Hayes Microcomputer Products"}
{0x0000dd, "TCL Incorporated"}
{0x0000de, "Cetia"}
{0x0000df, "Bell & Howell PUB SYS DIV"}
{0x0000e0, "Quadram"}
{0x0000e1, "Grid Systems"}
{0x0000e2, "Acer Technologies"}
{0x0000e3, "Integrated Micro Products"}
{0x0000e4, "IN2 Groupe Intertechnique"}
{0x0000e5, "Sigmex"}
{0x0000e6, "Aptor Produits DE Comm Indust"}
{0x0000e7, "Star Gate Technologies"}
{0x0000e8, "Accton Technology"}
{0x0000e9, "Isicad"}
{0x0000ea, "Upnod AB"}
{0x0000eb, "Matsushita COMM. IND. CO."}
{0x0000ec, "Microprocess"}
{0x0000ed, "April"}
{0x0000ee, "Network Designers"}
{0x0000ef, "KTI"}
{0x0000f0, "Samsung Electronics CO."}
{0x0000f1, "Magna Computer"}
{0x0000f2, "Spider Communications"}
{0x0000f3, "Gandalf Data Limited"}
{0x0000f4, "Allied Telesis"}
{0x0000f5, "Diamond Sales Limited"}
{0x0000f6, "Applied Microsystems"}
{0x0000f7, "Youth Keep Enterprise CO"}
{0x0000f8, "Digital Equipment"}
{0x0000f9, "Quotron Systems"}
{0x0000fa, "Microsage Computer Systems"}
{0x0000fb, "Rechner ZUR Kommunikation"}
{0x0000fc, "Meiko"}
{0x0000fd, "High Level Hardware"}
{0x0000fe, "Annapolis Micro Systems"}
{0x0000ff, "Camtec Electronics"}
{0x000100, "Equip'trans"}
{0x000101, "Private"}
{0x000102, "3com"}
{0x000103, "3com"}
{0x000104, "Dvico Co."}
{0x000105, "Beckhoff Automation GmbH"}
{0x000106, "Tews Datentechnik GmbH"}
{0x000107, "Leiser GmbH"}
{0x000108, "Avlab Technology"}
{0x000109, "Nagano Japan Radio Co."}
{0x00010a, "CIS Technology"}
{0x00010b, "Space CyberLink"}
{0x00010c, "System Talks"}
{0x00010d, "Coreco"}
{0x00010e, "Bri-Link Technologies Co."}
{0x00010f, "Brocade Communications Systems"}
{0x000110, "Gotham Networks"}
{0x000111, "iDigm"}
{0x000112, "Shark Multimedia"}
{0x000113, "Olympus"}
{0x000114, "Kanda Tsushin Kogyo CO."}
{0x000115, "Extratech"}
{0x000116, "Netspect Technologies"}
{0x000117, "Canal"}
{0x000118, "EZ Digital Co."}
{0x000119, "RTUnet (Australia)"}
{0x00011a, "EEH DataLink GmbH"}
{0x00011b, "Unizone Technologies"}
{0x00011c, "Universal Talkware"}
{0x00011d, "Centillium Communications"}
{0x00011e, "Precidia Technologies"}
{0x00011f, "RC Networks"}
{0x000120, "Oscilloquartz S.A."}
{0x000121, "Watchguard Technologies"}
{0x000122, "Trend Communications"}
{0x000123, "Digital Electronics"}
{0x000124, "Acer Incorporated"}
{0x000125, "Yaesu Musen CO."}
{0x000126, "PAC Labs"}
{0x000127, "Open Networks"}
{0x000128, "EnjoyWeb"}
{0x000129, "DFI"}
{0x00012a, "Telematica Sistems Inteligente"}
{0x00012b, "Telenet Co."}
{0x00012c, "Aravox Technologies"}
{0x00012d, "Komodo Technology"}
{0x00012e, "PC Partner"}
{0x00012f, "Twinhead International"}
{0x000130, "Extreme Networks"}
{0x000131, "Bosch Security Systems"}
{0x000132, "Dranetz - BMI"}
{0x000133, "Kyowa Electronic Instruments"}
{0x000134, "Selectron Systems AG"}
{0x000135, "KDC"}
{0x000136, "CyberTAN Technology"}
{0x000137, "IT Farm"}
{0x000138, "XAVi Technologies"}
{0x000139, "Point Multimedia Systems"}
{0x00013a, "Shelcad Communications"}
{0x00013b, "BNA Systems"}
{0x00013c, "TIW Systems"}
{0x00013d, "RiscStation"}
{0x00013e, "Ascom Tateco AB"}
{0x00013f, "Neighbor World Co."}
{0x000140, "Sendtek"}
{0x000141, "Cable Print"}
{0x000142, "Cisco Systems"}
{0x000143, "Cisco Systems"}
{0x000144, "EMC"}
{0x000145, "Winsystems"}
{0x000146, "Tesco Controls"}
{0x000147, "Zhone Technologies"}
{0x000148, "X-traWeb"}
{0x000149, "T.D.T. Transfer Data Test GmbH"}
{0x00014a, "Sony"}
{0x00014b, "Ennovate Networks"}
{0x00014c, "Berkeley Process Control"}
{0x00014d, "Shin Kin Enterprises Co."}
{0x00014e, "WIN Enterprises"}
{0x00014f, "Adtran"}
{0x000150, "Gilat Communications"}
{0x000151, "Ensemble Communications"}
{0x000152, "Chromatek"}
{0x000153, "Archtek Telecom"}
{0x000154, "G3M"}
{0x000155, "Promise Technology"}
{0x000156, "Firewiredirect.com"}
{0x000157, "Syswave CO."}
{0x000158, "Electro Industries/Gauge Tech"}
{0x000159, "S1"}
{0x00015a, "Digital Video Broadcasting"}
{0x00015b, "Italtel S.p.a/rf-up-i"}
{0x00015c, "Cadant"}
{0x00015d, "Oracle"}
{0x00015e, "Best Technology CO."}
{0x00015f, "Digital Design Gmbh"}
{0x000160, "Elmex Co."}
{0x000161, "Meta Machine Technology"}
{0x000162, "Cygnet Technologies"}
{0x000163, "Cisco Systems"}
{0x000164, "Cisco Systems"}
{0x000165, "AirSwitch"}
{0x000166, "TC Group A/S"}
{0x000167, "Hioki E.E."}
{0x000168, "Vitana"}
{0x000169, "Celestix Networks Pte"}
{0x00016a, "Alitec"}
{0x00016b, "LightChip"}
{0x00016c, "Foxconn"}
{0x00016d, "CarrierComm"}
{0x00016e, "Conklin"}
{0x00016f, "Inkel"}
{0x000170, "ESE Embedded System Engineer'g"}
{0x000171, "Allied Data Technologies"}
{0x000172, "TechnoLand Co."}
{0x000173, "Amcc"}
{0x000174, "CyberOptics"}
{0x000175, "Radiant Communications"}
{0x000176, "Orient Silver Enterprises"}
{0x000177, "Edsl"}
{0x000178, "Margi Systems"}
{0x000179, "Wireless Technology"}
{0x00017a, "Chengdu Maipu Electric Industrial Co."}
{0x00017b, "Heidelberger Druckmaschinen AG"}
{0x00017c, "AG-E GmbH"}
{0x00017d, "ThermoQuest"}
{0x00017e, "Adtek System Science Co."}
{0x00017f, "Experience Music Project"}
{0x000180, "AOpen"}
{0x000181, "Nortel Networks"}
{0x000182, "Dica Technologies AG"}
{0x000183, "Anite Telecoms"}
{0x000184, "Sieb & Meyer AG"}
{0x000185, "Hitachi Aloka Medical"}
{0x000186, "Uwe Disch"}
{0x000187, "i2SE GmbH"}
{0x000188, "Lxco Technologies ag"}
{0x000189, "Refraction Technology"}
{0x00018a, "ROI Computer AG"}
{0x00018b, "NetLinks Co."}
{0x00018c, "Mega Vision"}
{0x00018d, "AudeSi Technologies"}
{0x00018e, "Logitec"}
{0x00018f, "Kenetec"}
{0x000190, "Smk-m"}
{0x000191, "Syred Data Systems"}
{0x000192, "Texas Digital Systems"}
{0x000193, "Hanbyul Telecom Co."}
{0x000194, "Capital Equipment"}
{0x000195, "Sena Technologies"}
{0x000196, "Cisco Systems"}
{0x000197, "Cisco Systems"}
{0x000198, "Darim Vision"}
{0x000199, "HeiSei Electronics"}
{0x00019a, "Leunig Gmbh"}
{0x00019b, "Kyoto Microcomputer Co."}
{0x00019c, "JDS Uniphase"}
{0x00019d, "E-Control Systems"}
{0x00019e, "ESS Technology"}
{0x00019f, "Phonex Broadband"}
{0x0001a0, "Infinilink"}
{0x0001a1, "Mag-Tek"}
{0x0001a2, "Logical Co."}
{0x0001a3, "Genesys Logic"}
{0x0001a4, "Microlink"}
{0x0001a5, "Nextcomm"}
{0x0001a6, "Scientific-Atlanta Arcodan A/S"}
{0x0001a7, "Unex Technology"}
{0x0001a8, "Welltech Computer Co."}
{0x0001a9, "BMW AG"}
{0x0001aa, "Airspan Communications"}
{0x0001ab, "Main Street Networks"}
{0x0001ac, "Sitara Networks"}
{0x0001ad, "Coach Master International  d.b.a. CMI Worldwide"}
{0x0001ae, "Trex Enterprises"}
{0x0001af, "Emerson Network Power"}
{0x0001b0, "Fulltek Technology Co."}
{0x0001b1, "General Bandwidth"}
{0x0001b2, "Digital Processing Systems"}
{0x0001b3, "Precision Electronic Manufacturing"}
{0x0001b4, "Wayport"}
{0x0001b5, "Turin Networks"}
{0x0001b6, "Saejin T&M Co."}
{0x0001b7, "Centos"}
{0x0001b8, "Netsensity"}
{0x0001b9, "SKF Condition Monitoring"}
{0x0001ba, "IC-Net"}
{0x0001bb, "Frequentis"}
{0x0001bc, "Brains"}
{0x0001bd, "Peterson Electro-Musical Products"}
{0x0001be, "Gigalink Co."}
{0x0001bf, "Teleforce Co."}
{0x0001c0, "CompuLab"}
{0x0001c1, "Vitesse Semiconductor"}
{0x0001c2, "ARK Research"}
{0x0001c3, "Acromag"}
{0x0001c4, "NeoWave"}
{0x0001c5, "Simpler Networks"}
{0x0001c6, "Quarry Technologies"}
{0x0001c7, "Cisco Systems"}
{0x0001c8, "Thomas Conrad"}
{0x0001c8, "Conrad"}
{0x0001c9, "Cisco Systems"}
{0x0001ca, "Geocast Network Systems"}
{0x0001cb, "EVR"}
{0x0001cc, "Japan Total Design Communication Co."}
{0x0001cd, "ARtem"}
{0x0001ce, "Custom Micro Products"}
{0x0001cf, "Alpha Data Parallel Systems"}
{0x0001d0, "VitalPoint"}
{0x0001d1, "CoNet Communications"}
{0x0001d2, "inXtron"}
{0x0001d3, "Paxcomm"}
{0x0001d4, "Leisure Time"}
{0x0001d5, "Haedong Info & Comm CO."}
{0x0001d6, "manroland AG"}
{0x0001d7, "F5 Networks"}
{0x0001d8, "Teltronics"}
{0x0001d9, "Sigma"}
{0x0001da, "Wincomm"}
{0x0001db, "Freecom Technologies GmbH"}
{0x0001dc, "Activetelco"}
{0x0001dd, "Avail Networks"}
{0x0001de, "Trango Systems"}
{0x0001df, "Isdn Communications"}
{0x0001e0, "Fast Systems"}
{0x0001e1, "Kinpo Electronics"}
{0x0001e2, "Ando Electric"}
{0x0001e3, "Siemens AG"}
{0x0001e4, "Sitera"}
{0x0001e5, "Supernet"}
{0x0001e6, "Hewlett-Packard Company"}
{0x0001e7, "Hewlett-Packard Company"}
{0x0001e8, "Force10 Networks"}
{0x0001e9, "Litton Marine Systems B.V."}
{0x0001ea, "Cirilium"}
{0x0001eb, "C-COM"}
{0x0001ec, "Ericsson Group"}
{0x0001ed, "Seta"}
{0x0001ee, "Comtrol Europe"}
{0x0001ef, "Camtel Technology"}
{0x0001f0, "Tridium"}
{0x0001f1, "Innovative Concepts"}
{0x0001f2, "Mark of the Unicorn"}
{0x0001f3, "QPS"}
{0x0001f4, "Enterasys Networks"}
{0x0001f5, "Erim S.A."}
{0x0001f6, "Association of Musical Electronics Industry"}
{0x0001f7, "Image Display Systems"}
{0x0001f8, "Adherent Systems"}
{0x0001f9, "TeraGlobal Communications"}
{0x0001fa, "Horoscas"}
{0x0001fb, "DoTop Technology"}
{0x0001fc, "Keyence"}
{0x0001fd, "Digital Voice Systems"}
{0x0001fe, "Digital Equipment"}
{0x0001ff, "Data Direct Networks"}
{0x000200, "Net & Sys Co."}
{0x000201, "IFM Electronic gmbh"}
{0x000202, "Amino Communications"}
{0x000203, "Woonsang Telecom"}
{0x000204, "Bodmann Industries Elektronik GmbH"}
{0x000205, "Hitachi Denshi"}
{0x000206, "Telital R&D Denmark A/S"}
{0x000207, "VisionGlobal Network"}
{0x000208, "Unify Networks"}
{0x000209, "Shenzhen SED Information Technology Co."}
{0x00020a, "Gefran Spa"}
{0x00020b, "Native Networks"}
{0x00020c, "Metro-Optix"}
{0x00020d, "Micronpc.com"}
{0x00020e, "ECI Telecom,, NSD-US"}
{0x00020f, "Aatr"}
{0x000210, "Fenecom"}
{0x000211, "Nature Worldwide Technology"}
{0x000212, "SierraCom"}
{0x000213, "S.d.e.l."}
{0x000214, "Dtvro"}
{0x000215, "Cotas Computer Technology A/B"}
{0x000216, "Cisco Systems"}
{0x000217, "Cisco Systems"}
{0x000218, "Advanced Scientific"}
{0x000219, "Paralon Technologies"}
{0x00021a, "Zuma Networks"}
{0x00021b, "Kollmorgen-Servotronix"}
{0x00021c, "Network Elements"}
{0x00021d, "Data General Communication"}
{0x00021e, "Simtel S.r.l."}
{0x00021f, "Aculab PLC"}
{0x000220, "Canon Finetech"}
{0x000221, "DSP Application"}
{0x000222, "Chromisys"}
{0x000223, "ClickTV"}
{0x000224, "C-cor"}
{0x000225, "One Stop Systems"}
{0x000226, "XESystems"}
{0x000227, "ESD Electronic System Design GmbH"}
{0x000228, "Necsom"}
{0x000229, "Adtec"}
{0x00022a, "Asound Electronic"}
{0x00022b, "SAXA"}
{0x00022c, "ABB Bomem"}
{0x00022d, "Agere Systems"}
{0x00022e, "Teac R&"}
{0x00022f, "P-Cube"}
{0x000230, "Intersoft Electronics"}
{0x000231, "Ingersoll-Rand"}
{0x000232, "Avision"}
{0x000233, "Mantra Communications"}
{0x000234, "Imperial Technology"}
{0x000235, "Paragon Networks International"}
{0x000236, "Init Gmbh"}
{0x000237, "Cosmo Research"}
{0x000238, "Serome Technology"}
{0x000239, "Visicom"}
{0x00023a, "ZSK Stickmaschinen GmbH"}
{0x00023b, "Ericsson"}
{0x00023c, "Creative Technology"}
{0x00023d, "Cisco Systems"}
{0x00023e, "Selta Telematica S.p.a"}
{0x00023f, "Compal Electronics"}
{0x000240, "Seedek Co."}
{0x000241, "Amer.com"}
{0x000242, "Videoframe Systems"}
{0x000243, "Raysis Co."}
{0x000244, "Surecom Technology Co."}
{0x000245, "Lampus Co"}
{0x000246, "All-Win Tech Co."}
{0x000247, "Great Dragon Information Technology (Group) Co."}
{0x000248, "Pilz GmbH & Co."}
{0x000249, "Aviv Infocom Co"}
{0x00024a, "Cisco Systems"}
{0x00024b, "Cisco Systems"}
{0x00024c, "SiByte"}
{0x00024d, "Mannesman Dematic Colby"}
{0x00024e, "Datacard Group"}
{0x00024f, "IPM Datacom S.R.L."}
{0x000250, "Geyser Networks"}
{0x000251, "Soma Networks"}
{0x000252, "Carrier"}
{0x000253, "Televideo"}
{0x000254, "WorldGate"}
{0x000255, "IBM"}
{0x000256, "Alpha Processor"}
{0x000257, "Microcom"}
{0x000258, "Flying Packets Communications"}
{0x000259, "Tsann Kuen China (Shanghai)Enterprise Co., IT Group"}
{0x00025a, "Catena Networks"}
{0x00025b, "Cambridge Silicon Radio"}
{0x00025c, "SCI Systems (Kunshan) Co."}
{0x00025d, "Calix Networks"}
{0x00025e, "High Technology"}
{0x00025f, "Nortel Networks"}
{0x000260, "Accordion Networks"}
{0x000261, "Tilgin AB"}
{0x000262, "Soyo Group Soyo Com Tech Co."}
{0x000263, "UPS Manufacturing SRL"}
{0x000264, "AudioRamp.com"}
{0x000265, "Virditech Co."}
{0x000266, "Thermalogic"}
{0x000267, "Node Runner"}
{0x000268, "Harris Government Communications"}
{0x000269, "Nadatel Co."}
{0x00026a, "Cocess Telecom Co."}
{0x00026b, "BCM Computers Co."}
{0x00026c, "Philips CFT"}
{0x00026d, "Adept Telecom"}
{0x00026e, "NeGeN Access"}
{0x00026f, "Senao International Co."}
{0x000270, "Crewave Co."}
{0x000271, "Zhone Technologies"}
{0x000272, "CC&C Technologies"}
{0x000273, "Coriolis Networks"}
{0x000274, "Tommy Technologies"}
{0x000275, "Smart Technologies"}
{0x000276, "Primax Electronics"}
{0x000277, "Cash Systemes Industrie"}
{0x000278, "Samsung Electro-Mechanics Co."}
{0x000279, "Control Applications"}
{0x00027a, "IOI Technology"}
{0x00027b, "Amplify Net"}
{0x00027c, "Trilithic"}
{0x00027d, "Cisco Systems"}
{0x00027e, "Cisco Systems"}
{0x00027f, "ask-technologies.com"}
{0x000280, "Mu Net"}
{0x000281, "Madge"}
{0x000282, "ViaClix"}
{0x000283, "Spectrum Controls"}
{0x000284, "Areva T&D"}
{0x000285, "Riverstone Networks"}
{0x000286, "Occam Networks"}
{0x000287, "Adapcom"}
{0x000288, "Global Village Communication"}
{0x000289, "DNE Technologies"}
{0x00028a, "Ambit Microsystems"}
{0x00028b, "Vdsl Systems OY"}
{0x00028c, "Micrel-Synergy Semiconductor"}
{0x00028d, "Movita Technologies"}
{0x00028e, "Rapid 5 Networks"}
{0x00028f, "Globetek"}
{0x000290, "Woorigisool"}
{0x000291, "Open Network Co."}
{0x000292, "Logic Innovations"}
{0x000293, "Solid Data Systems"}
{0x000294, "Tokyo Sokushin Co."}
{0x000295, "IP.Access Limited"}
{0x000296, "Lectron Co"}
{0x000297, "C-COR.net"}
{0x000298, "Broadframe"}
{0x000299, "Apex"}
{0x00029a, "Storage Apps"}
{0x00029b, "Kreatel Communications AB"}
{0x00029c, "3com"}
{0x00029d, "Merix"}
{0x00029e, "Information Equipment Co."}
{0x00029f, "L-3 Communication Aviation Recorders"}
{0x0002a0, "Flatstack"}
{0x0002a1, "World Wide Packets"}
{0x0002a2, "Hilscher GmbH"}
{0x0002a3, "ABB Switzerland, Power Systems"}
{0x0002a4, "AddPac Technology Co."}
{0x0002a5, "Hewlett-Packard Company"}
{0x0002a6, "Effinet Systems Co."}
{0x0002a7, "Vivace Networks"}
{0x0002a8, "Air Link Technology"}
{0x0002a9, "Racom, S.r.o."}
{0x0002aa, "PLcom Co."}
{0x0002ab, "CTC Union Technologies Co."}
{0x0002ac, "3PAR data"}
{0x0002ad, "Hoya"}
{0x0002ae, "Scannex Electronics"}
{0x0002af, "TeleCruz Technology"}
{0x0002b0, "Hokubu Communication & Industrial Co."}
{0x0002b1, "Anritsu"}
{0x0002b2, "Cablevision"}
{0x0002b3, "Intel"}
{0x0002b4, "Daphne"}
{0x0002b5, "Avnet"}
{0x0002b6, "Acrosser Technology Co."}
{0x0002b7, "Watanabe Electric Industry Co."}
{0x0002b8, "WHI Konsult AB"}
{0x0002b9, "Cisco Systems"}
{0x0002ba, "Cisco Systems"}
{0x0002bb, "Continuous Computing"}
{0x0002bc, "LVL 7 Systems"}
{0x0002bd, "Bionet Co."}
{0x0002be, "Totsu Engineering"}
{0x0002bf, "dotRocket"}
{0x0002c0, "Bencent Tzeng Industry Co."}
{0x0002c1, "Innovative Electronic Designs"}
{0x0002c2, "Net Vision Telecom"}
{0x0002c3, "Arelnet"}
{0x0002c4, "Vector International Bvba"}
{0x0002c5, "Evertz Microsystems"}
{0x0002c6, "Data Track Technology PLC"}
{0x0002c7, "Alps Electric Co."}
{0x0002c8, "Technocom Communications Technology (pte)"}
{0x0002c9, "Mellanox Technologies"}
{0x0002ca, "EndPoints"}
{0x0002cb, "TriState"}
{0x0002cc, "M.c.c.i"}
{0x0002cd, "TeleDream"}
{0x0002ce, "FoxJet"}
{0x0002cf, "ZyGate Communications"}
{0x0002d0, "Comdial"}
{0x0002d1, "Vivotek"}
{0x0002d2, "Workstation AG"}
{0x0002d3, "NetBotz"}
{0x0002d4, "PDA Peripherals"}
{0x0002d5, "ACR"}
{0x0002d6, "Nice Systems"}
{0x0002d7, "Empeg"}
{0x0002d8, "Brecis Communications"}
{0x0002d9, "Reliable Controls"}
{0x0002da, "ExiO Communications"}
{0x0002db, "Netsec"}
{0x0002dc, "Fujitsu General Limited"}
{0x0002dd, "Bromax Communications"}
{0x0002de, "Astrodesign"}
{0x0002df, "Net Com Systems"}
{0x0002e0, "Etas Gmbh"}
{0x0002e1, "Integrated Network"}
{0x0002e2, "NDC Infared Engineering"}
{0x0002e3, "Lite-on Communications"}
{0x0002e4, "JC Hyun Systems"}
{0x0002e5, "Timeware"}
{0x0002e6, "Gould Instrument Systems"}
{0x0002e7, "CAB GmbH & Co KG"}
{0x0002e8, "E.d.&a."}
{0x0002e9, "CS Systemes De Securite - C3S"}
{0x0002ea, "Focus Enhancements"}
{0x0002eb, "Pico Communications"}
{0x0002ec, "Maschoff Design Engineering"}
{0x0002ed, "DXO Telecom Co."}
{0x0002ee, "Nokia Danmark A/S"}
{0x0002ef, "CCC Network Systems Group"}
{0x0002f0, "AME Optimedia Technology Co."}
{0x0002f1, "Pinetron Co."}
{0x0002f2, "eDevice"}
{0x0002f3, "Media Serve Co."}
{0x0002f4, "Pctel"}
{0x0002f5, "Vive Synergies"}
{0x0002f6, "Equipe Communications"}
{0x0002f7, "ARM"}
{0x0002f8, "Seakr Engineering"}
{0x0002f9, "Mimos Semiconductor SDN BHD"}
{0x0002fa, "DX Antenna Co."}
{0x0002fb, "Baumuller Aulugen-Systemtechnik GmbH"}
{0x0002fc, "Cisco Systems"}
{0x0002fd, "Cisco Systems"}
{0x0002fe, "Viditec"}
{0x0002ff, "Handan BroadInfoCom"}
{0x000300, "Barracuda Networks"}
{0x000301, "Avantas Networks"}
{0x000302, "Charles Industries"}
{0x000303, "Jama Electronics Co."}
{0x000304, "Pacific Broadband Communications"}
{0x000305, "MSC Vertriebs GmbH"}
{0x000306, "Fusion In Tech Co."}
{0x000307, "Secure Works"}
{0x000308, "AM Communications"}
{0x000309, "Texcel Technology PLC"}
{0x00030a, "Argus Technologies"}
{0x00030b, "Hunter Technology"}
{0x00030c, "Telesoft Technologies"}
{0x00030d, "Uniwill Computer"}
{0x00030e, "Core Communications Co."}
{0x00030f, "Digital China (Shanghai) Networks"}
{0x000310, "ITX E-Globaledge"}
{0x000311, "Micro Technology Co."}
{0x000312, "TR-Systemtechnik GmbH"}
{0x000313, "Access Media SPA"}
{0x000314, "Teleware Network Systems"}
{0x000315, "Cidco Incorporated"}
{0x000316, "Nobell Communications"}
{0x000317, "Merlin Systems"}
{0x000318, "Cyras Systems"}
{0x000319, "Infineon AG"}
{0x00031a, "Beijing Broad Telecom"}
{0x00031b, "Cellvision Systems"}
{0x00031c, "Svenska Hardvarufabriken AB"}
{0x00031d, "Taiwan Commate Computer"}
{0x00031e, "Optranet"}
{0x00031f, "Condev"}
{0x000320, "Xpeed"}
{0x000321, "Reco Research Co."}
{0x000322, "Idis Co."}
{0x000323, "Cornet Technology"}
{0x000324, "Sanyo Consumer Electronics Co."}
{0x000325, "Arima Computer"}
{0x000326, "Iwasaki Information Systems Co."}
{0x000327, "Act'l"}
{0x000328, "Mace Group"}
{0x000329, "F3"}
{0x00032a, "UniData Communication Systems"}
{0x00032b, "GAI Datenfunksysteme GmbH"}
{0x00032c, "ABB Switzerland"}
{0x00032d, "Ibase Technology"}
{0x00032e, "Scope Information Management"}
{0x00032f, "Global Sun Technology"}
{0x000330, "Imagenics, Co."}
{0x000331, "Cisco Systems"}
{0x000332, "Cisco Systems"}
{0x000333, "Digitel Co."}
{0x000334, "Newport Electronics"}
{0x000335, "Mirae Technology"}
{0x000336, "Zetes Technologies"}
{0x000337, "Vaone"}
{0x000338, "Oak Technology"}
{0x000339, "Eurologic Systems"}
{0x00033a, "Silicon Wave"}
{0x00033b, "Tami Tech Co."}
{0x00033c, "Daiden Co."}
{0x00033d, "Ilshin Lab"}
{0x00033e, "Tateyama System Laboratory Co."}
{0x00033f, "BigBand Networks"}
{0x000340, "Floware Wireless Systems"}
{0x000341, "Axon Digital Design"}
{0x000342, "Nortel Networks"}
{0x000343, "Martin Professional A/S"}
{0x000344, "Tietech.Co."}
{0x000345, "Routrek Networks"}
{0x000346, "Hitachi Kokusai Electric"}
{0x000347, "Intel"}
{0x000348, "Norscan Instruments"}
{0x000349, "Vidicode Datacommunicatie B.V."}
{0x00034a, "Rias"}
{0x00034b, "Nortel Networks"}
{0x00034c, "Shanghai DigiVision Technology Co."}
{0x00034d, "Chiaro Networks"}
{0x00034e, "Pos Data Company"}
{0x00034f, "Sur-Gard Security"}
{0x000350, "Bticino SPA"}
{0x000351, "Diebold"}
{0x000352, "Colubris Networks"}
{0x000353, "Mitac"}
{0x000354, "Fiber Logic Communications"}
{0x000355, "TeraBeam Internet Systems"}
{0x000356, "Wincor Nixdorf International GmbH"}
{0x000357, "Intervoice-Brite"}
{0x000358, "Hanyang Digitech Co."}
{0x000359, "DigitalSis"}
{0x00035a, "Photron Limited"}
{0x00035b, "BridgeWave Communications"}
{0x00035c, "Saint Song"}
{0x00035d, "Bosung Hi-Net Co."}
{0x00035e, "Metropolitan Area Networks"}
{0x00035f, "Prueftechnik Condition Monitoring GmbH & Co. KG"}
{0x000360, "PAC Interactive Technology"}
{0x000361, "Widcomm"}
{0x000362, "Vodtel Communications"}
{0x000363, "Miraesys Co."}
{0x000364, "Scenix Semiconductor"}
{0x000365, "Kira Information & Communications"}
{0x000366, "ASM Pacific Technology"}
{0x000367, "Jasmine Networks"}
{0x000368, "Embedone Co."}
{0x000369, "Nippon Antenna Co."}
{0x00036a, "Mainnet"}
{0x00036b, "Cisco Systems"}
{0x00036c, "Cisco Systems"}
{0x00036d, "Runtop"}
{0x00036e, "Nicon Systems (Pty) Limited"}
{0x00036f, "Telsey SPA"}
{0x000370, "NXTV"}
{0x000371, "Acomz Networks"}
{0x000372, "Ulan"}
{0x000373, "Aselsan A.S"}
{0x000374, "Control Microsystems"}
{0x000375, "NetMedia"}
{0x000376, "Graphtec Technology"}
{0x000377, "Gigabit Wireless"}
{0x000378, "Humax Co."}
{0x000379, "Proscend Communications"}
{0x00037a, "Taiyo Yuden Co."}
{0x00037b, "Idec Izumi"}
{0x00037c, "Coax Media"}
{0x00037d, "Stellcom"}
{0x00037e, "Portech Communications"}
{0x00037f, "Atheros Communications"}
{0x000380, "SSH Communications Security"}
{0x000381, "Ingenico International"}
{0x000382, "A-One Co."}
{0x000383, "Metera Networks"}
{0x000384, "Aeta"}
{0x000385, "Actelis Networks"}
{0x000386, "Ho Net"}
{0x000387, "Blaze Network Products"}
{0x000388, "Fastfame Technology Co."}
{0x000389, "Plantronics"}
{0x00038a, "America Online"}
{0x00038b, "Plus-one I&T"}
{0x00038c, "Total Impact"}
{0x00038d, "PCS Revenue Control Systems"}
{0x00038e, "Atoga Systems"}
{0x00038f, "Weinschel"}
{0x000390, "Digital Video Communications"}
{0x000391, "Advanced Digital Broadcast"}
{0x000392, "Hyundai Teletek Co."}
{0x000393, "Apple Computer"}
{0x000394, "Connect One"}
{0x000395, "California Amplifier"}
{0x000396, "EZ Cast Co."}
{0x000397, "Watchfront Limited"}
{0x000398, "Wisi"}
{0x000399, "Dongju Informations & Communications Co."}
{0x00039a, "SiConnect"}
{0x00039b, "NetChip Technology"}
{0x00039c, "OptiMight Communications"}
{0x00039d, "Qisda"}
{0x00039e, "Tera System Co."}
{0x00039f, "Cisco Systems"}
{0x0003a0, "Cisco Systems"}
{0x0003a1, "Hiper Information & Communication"}
{0x0003a2, "Catapult Communications"}
{0x0003a3, "Mavix"}
{0x0003a4, "Imation"}
{0x0003a5, "Medea"}
{0x0003a6, "Traxit Technology"}
{0x0003a7, "Unixtar Technology"}
{0x0003a8, "Idot Computers"}
{0x0003a9, "Axcent Media AG"}
{0x0003aa, "Watlow"}
{0x0003ab, "Bridge Information Systems"}
{0x0003ac, "Fronius Schweissmaschinen"}
{0x0003ad, "Emerson Energy Systems AB"}
{0x0003ae, "Allied Advanced Manufacturing Pte"}
{0x0003af, "Paragea Communications"}
{0x0003b0, "Xsense Technology"}
{0x0003b1, "Hospira"}
{0x0003b2, "Radware"}
{0x0003b3, "IA Link Systems Co."}
{0x0003b4, "Macrotek International"}
{0x0003b5, "Entra Technology Co."}
{0x0003b6, "QSI"}
{0x0003b7, "Zaccess Systems"}
{0x0003b8, "NetKit Solutions"}
{0x0003b9, "Hualong Telecom Co."}
{0x0003ba, "Oracle"}
{0x0003bb, "Signal Communications Limited"}
{0x0003bc, "COT GmbH"}
{0x0003bd, "OmniCluster Technologies"}
{0x0003be, "Netility"}
{0x0003bf, "Centerpoint Broadband Technologies"}
{0x0003c0, "Rftnc Co."}
{0x0003c1, "Packet Dynamics"}
{0x0003c2, "Solphone K.K."}
{0x0003c3, "Micronik Multimedia"}
{0x0003c4, "Tomra Systems ASA"}
{0x0003c5, "Mobotix AG"}
{0x0003c6, "Icue Systems"}
{0x0003c7, "hopf Elektronik GmbH"}
{0x0003c8, "CML Emergency Services"}
{0x0003c9, "Tecom Co."}
{0x0003ca, "MTS Systems"}
{0x0003cb, "Nippon Systems Development Co."}
{0x0003cc, "Momentum Computer"}
{0x0003cd, "Clovertech"}
{0x0003ce, "Eten Technologies"}
{0x0003cf, "Muxcom"}
{0x0003d0, "Koankeiso Co."}
{0x0003d1, "Takaya"}
{0x0003d2, "Crossbeam Systems"}
{0x0003d3, "Internet Energy Systems"}
{0x0003d4, "Alloptic"}
{0x0003d5, "Advanced Communications Co."}
{0x0003d6, "Radvision"}
{0x0003d7, "NextNet Wireless"}
{0x0003d8, "iMPath Networks"}
{0x0003d9, "Secheron SA"}
{0x0003da, "Takamisawa Cybernetics Co."}
{0x0003db, "Apogee Electronics"}
{0x0003dc, "Lexar Media"}
{0x0003dd, "Comark"}
{0x0003de, "OTC Wireless"}
{0x0003df, "Desana Systems"}
{0x0003e0, "Motorola"}
{0x0003e1, "Winmate Communication"}
{0x0003e2, "Comspace"}
{0x0003e3, "Cisco Systems"}
{0x0003e4, "Cisco Systems"}
{0x0003e5, "Hermstedt SG"}
{0x0003e6, "Entone"}
{0x0003e7, "Logostek Co."}
{0x0003e8, "Wavelength Digital Limited"}
{0x0003e9, "Akara Canada"}
{0x0003ea, "Mega System Technologies"}
{0x0003eb, "Atrica"}
{0x0003ec, "ICG Research"}
{0x0003ed, "Shinkawa Electric Co."}
{0x0003ee, "MKNet"}
{0x0003ef, "Oneline AG"}
{0x0003f0, "Redfern Broadband Networks"}
{0x0003f1, "Cicada Semiconductor"}
{0x0003f2, "Seneca Networks"}
{0x0003f3, "Dazzle Multimedia"}
{0x0003f4, "NetBurner"}
{0x0003f5, "Chip2Chip"}
{0x0003f6, "Allegro Networks"}
{0x0003f7, "Plast-Control GmbH"}
{0x0003f8, "SanCastle Technologies"}
{0x0003f9, "Pleiades Communications"}
{0x0003fa, "TiMetra Networks"}
{0x0003fb, "Enegate Co."}
{0x0003fc, "Intertex Data AB"}
{0x0003fd, "Cisco Systems"}
{0x0003fe, "Cisco Systems"}
{0x0003ff, "Microsoft"}
{0x000400, "Lexmark International"}
{0x000401, "Osaki Electric Co."}
{0x000402, "Nexsan Technologies"}
{0x000403, "Nexsi"}
{0x000404, "Makino Milling Machine Co."}
{0x000405, "ACN Technologies"}
{0x000406, "Fa. Metabox AG"}
{0x000407, "Topcon Positioning Systems"}
{0x000408, "Sanko Electronics Co."}
{0x000409, "Cratos Networks"}
{0x00040a, "Sage Systems"}
{0x00040b, "3com Europe"}
{0x00040c, "Kanno Work's"}
{0x00040d, "Avaya"}
{0x00040e, "AVM GmbH"}
{0x00040f, "Asus Network Technologies"}
{0x000410, "Spinnaker Networks"}
{0x000411, "Inkra Networks"}
{0x000412, "WaveSmith Networks"}
{0x000413, "Snom Technology AG"}
{0x000414, "Umezawa Musen Denki Co."}
{0x000415, "Rasteme Systems Co."}
{0x000416, "Parks S/A Comunicacoes Digitais"}
{0x000417, "Elau AG"}
{0x000418, "TeltronicU."}
{0x000419, "Fibercycle Networks"}
{0x00041a, "Ines Test and Measurement GmbH & CoKG"}
{0x00041b, "Bridgeworks"}
{0x00041c, "ipDialog"}
{0x00041d, "Corega of America"}
{0x00041e, "Shikoku Instrumentation Co."}
{0x00041f, "Sony Computer Entertainment"}
{0x000420, "Slim Devices"}
{0x000421, "Ocular Networks"}
{0x000422, "Gordon Kapes"}
{0x000423, "Intel"}
{0x000424, "TMC s.r.l."}
{0x000425, "Atmel"}
{0x000426, "Autosys"}
{0x000427, "Cisco Systems"}
{0x000428, "Cisco Systems"}
{0x000429, "Pixord"}
{0x00042a, "Wireless Networks"}
{0x00042b, "IT Access Co."}
{0x00042c, "Minet"}
{0x00042d, "Sarian Systems"}
{0x00042e, "Netous Technologies"}
{0x00042f, "International Communications Products"}
{0x000430, "Netgem"}
{0x000431, "GlobalStreams"}
{0x000432, "Voyetra Turtle Beach"}
{0x000433, "Cyberboard A/S"}
{0x000434, "Accelent Systems"}
{0x000435, "Comptek International"}
{0x000436, "Elansat Technologies"}
{0x000437, "Powin Information Technology"}
{0x000438, "Nortel Networks"}
{0x000439, "Rosco Entertainment Technology"}
{0x00043a, "Intelligent Telecommunications"}
{0x00043b, "Lava Computer Mfg."}
{0x00043c, "Sonos Co."}
{0x00043d, "Indel AG"}
{0x00043e, "Telencomm"}
{0x00043f, "ESTeem Wireless Modems"}
{0x000440, "cyberPIXIE"}
{0x000441, "Half Dome Systems"}
{0x000442, "Nact"}
{0x000443, "Agilent Technologies"}
{0x000444, "Western Multiplex"}
{0x000445, "LMS Skalar Instruments GmbH"}
{0x000446, "Cyzentech Co."}
{0x000447, "Acrowave Systems Co."}
{0x000448, "Polaroid"}
{0x000449, "Mapletree Networks"}
{0x00044a, "iPolicy Networks"}
{0x00044b, "Nvidia"}
{0x00044c, "Jenoptik"}
{0x00044d, "Cisco Systems"}
{0x00044e, "Cisco Systems"}
{0x00044f, "Leukhardt Systemelektronik GmbH"}
{0x000450, "DMD Computers SRL"}
{0x000451, "Medrad"}
{0x000452, "RocketLogix"}
{0x000453, "YottaYotta"}
{0x000454, "Quadriga UK"}
{0x000455, "Antara.net"}
{0x000456, "Cambium Networks Limited"}
{0x000457, "Universal Access Technology"}
{0x000458, "Fusion X Co."}
{0x000459, "Veristar"}
{0x00045a, "The Linksys Group"}
{0x00045b, "Techsan Electronics Co."}
{0x00045c, "Mobiwave Pte"}
{0x00045d, "Beka Elektronik"}
{0x00045e, "PolyTrax Information Technology AG"}
{0x00045f, "Evalue Technology"}
{0x000460, "Knilink Technology"}
{0x000461, "Epox Computer Co."}
{0x000462, "Dakos Data & Communication Co."}
{0x000463, "Bosch Security Systems"}
{0x000464, "Fantasma Networks"}
{0x000465, "i.s.t isdn-support technik GmbH"}
{0x000466, "Armitel Co."}
{0x000467, "Wuhan Research Institute of MII"}
{0x000468, "Vivity"}
{0x000469, "Innocom"}
{0x00046a, "Navini Networks"}
{0x00046b, "Palm Wireless"}
{0x00046c, "Cyber Technology Co."}
{0x00046d, "Cisco Systems"}
{0x00046e, "Cisco Systems"}
{0x00046f, "Digitel S/A Industria Eletronica"}
{0x000470, "ipUnplugged AB"}
{0x000471, "IPrad"}
{0x000472, "Telelynx"}
{0x000473, "Photonex"}
{0x000474, "Legrand"}
{0x000475, "3 Com"}
{0x000476, "3 Com"}
{0x000477, "Scalant Systems"}
{0x000478, "G. Star Technology"}
{0x000479, "Radius Co."}
{0x00047a, "Axxessit ASA"}
{0x00047b, "Schlumberger"}
{0x00047c, "Skidata AG"}
{0x00047d, "Pelco"}
{0x00047e, "Siqura B.V."}
{0x00047f, "Chr. Mayr GmbH & Co. KG"}
{0x000480, "Brocade Communications Systems"}
{0x000481, "Econolite Control Products"}
{0x000482, "Medialogic"}
{0x000483, "Deltron Technology"}
{0x000484, "Amann GmbH"}
{0x000485, "PicoLight"}
{0x000486, "ITTC, University of Kansas"}
{0x000487, "Cogency Semiconductor"}
{0x000488, "Eurotherm Controls"}
{0x000489, "Yafo Networks"}
{0x00048a, "Temia Vertriebs GmbH"}
{0x00048b, "Poscon"}
{0x00048c, "Nayna Networks"}
{0x00048d, "Tone Commander Systems"}
{0x00048e, "Ohm Tech Labs"}
{0x00048f, "TD Systems"}
{0x000490, "Optical Access"}
{0x000491, "Technovision"}
{0x000492, "Hive Internet"}
{0x000493, "Tsinghua Unisplendour Co."}
{0x000494, "Breezecom"}
{0x000495, "Tejas Networks India Limited"}
{0x000496, "Extreme Networks"}
{0x000497, "MacroSystem Digital Video AG"}
{0x000498, "Mahi Networks"}
{0x000499, "Chino"}
{0x00049a, "Cisco Systems"}
{0x00049b, "Cisco Systems"}
{0x00049c, "Surgient Networks"}
{0x00049d, "Ipanema Technologies"}
{0x00049e, "Wirelink Co."}
{0x00049f, "Freescale Semiconductor"}
{0x0004a0, "Verity Instruments"}
{0x0004a1, "Pathway Connectivity"}
{0x0004a2, "L.S.I. Japan Co."}
{0x0004a3, "Microchip Technology"}
{0x0004a4, "NetEnabled"}
{0x0004a5, "Barco Projection Systems NV"}
{0x0004a6, "SAF Tehnika"}
{0x0004a7, "FabiaTech"}
{0x0004a8, "Broadmax Technologies"}
{0x0004a9, "SandStream Technologies"}
{0x0004aa, "Jetstream Communications"}
{0x0004ab, "Comverse Network Systems"}
{0x0004ac, "IBM"}
{0x0004ad, "Malibu Networks"}
{0x0004ae, "Sullair"}
{0x0004af, "Digital Fountain"}
{0x0004b0, "Elesign Co."}
{0x0004b1, "Signal Technology"}
{0x0004b2, "Essegi SRL"}
{0x0004b3, "Videotek"}
{0x0004b4, "Ciac"}
{0x0004b5, "Equitrac"}
{0x0004b6, "Stratex Networks"}
{0x0004b7, "AMB i.t. Holding"}
{0x0004b8, "Kumahira Co."}
{0x0004b9, "S.I. Soubou"}
{0x0004ba, "KDD Media Will"}
{0x0004bb, "Bardac"}
{0x0004bc, "Giantec"}
{0x0004bd, "Motorola Mobility"}
{0x0004be, "OptXCon"}
{0x0004bf, "VersaLogic"}
{0x0004c0, "Cisco Systems"}
{0x0004c1, "Cisco Systems"}
{0x0004c2, "Magnipix"}
{0x0004c3, "Castor Informatique"}
{0x0004c4, "Allen & Heath Limited"}
{0x0004c5, "ASE Technologies"}
{0x0004c6, "Yamaha Motor Co."}
{0x0004c7, "NetMount"}
{0x0004c8, "Liba Maschinenfabrik Gmbh"}
{0x0004c9, "Micro Electron Co."}
{0x0004ca, "FreeMs"}
{0x0004cb, "Tdsoft Communication"}
{0x0004cc, "Peek Traffic B.V."}
{0x0004cd, "Informedia Research Group"}
{0x0004ce, "Patria Ailon"}
{0x0004cf, "Seagate Technology"}
{0x0004d0, "Softlink s.r.o."}
{0x0004d1, "Drew Technologies"}
{0x0004d2, "Adcon Telemetry GmbH"}
{0x0004d3, "Toyokeiki Co."}
{0x0004d4, "Proview Electronics Co."}
{0x0004d5, "Hitachi Information & Communication Engineering"}
{0x0004d6, "Takagi Industrial Co."}
{0x0004d7, "Omitec Instrumentation"}
{0x0004d8, "IPWireless"}
{0x0004d9, "Titan Electronics"}
{0x0004da, "Relax Technology"}
{0x0004db, "Tellus Group"}
{0x0004dc, "Nortel Networks"}
{0x0004dd, "Cisco Systems"}
{0x0004de, "Cisco Systems"}
{0x0004df, "Teracom Telematica Ltda."}
{0x0004e0, "Procket Networks"}
{0x0004e1, "Infinior Microsystems"}
{0x0004e2, "SMC Networks"}
{0x0004e3, "Accton Technology"}
{0x0004e4, "Daeryung Ind."}
{0x0004e5, "Glonet Systems"}
{0x0004e6, "Banyan Network Private Limited"}
{0x0004e7, "Lightpointe Communications"}
{0x0004e8, "IER"}
{0x0004e9, "Infiniswitch"}
{0x0004ea, "Hewlett-Packard Company"}
{0x0004eb, "Paxonet Communications"}
{0x0004ec, "Memobox SA"}
{0x0004ed, "Billion Electric Co."}
{0x0004ee, "Lincoln Electric Company"}
{0x0004ef, "Polestar"}
{0x0004f0, "International Computers"}
{0x0004f1, "WhereNet"}
{0x0004f2, "Polycom"}
{0x0004f3, "FS Forth-systeme Gmbh"}
{0x0004f4, "Infinite Electronics"}
{0x0004f5, "SnowShore Networks"}
{0x0004f6, "Amphus"}
{0x0004f7, "Omega Band"}
{0x0004f8, "Qualicable TV Industria E Com."}
{0x0004f9, "Xtera Communications"}
{0x0004fa, "NBS Technologies"}
{0x0004fb, "Commtech"}
{0x0004fc, "Stratus Computer (DE)"}
{0x0004fd, "Japan Control Engineering Co."}
{0x0004fe, "Pelago Networks"}
{0x0004ff, "Acronet Co."}
{0x000500, "Cisco Systems"}
{0x000501, "Cisco Systems"}
{0x000502, "Apple Computer"}
{0x000503, "Iconag"}
{0x000504, "Naray Information & Communication Enterprise"}
{0x000505, "Systems Integration Solutions"}
{0x000506, "Reddo Networks AB"}
{0x000507, "Fine Appliance"}
{0x000508, "Inetcam"}
{0x000509, "Avoc Nishimura"}
{0x00050a, "ICS Spa"}
{0x00050b, "Sicom Systems"}
{0x00050c, "Network Photonics"}
{0x00050d, "Midstream Technologies"}
{0x00050e, "3ware"}
{0x00050f, "Tanaka S/S"}
{0x000510, "Infinite Shanghai Communication Terminals"}
{0x000511, "Complementary Technologies"}
{0x000512, "MeshNetworks"}
{0x000513, "VTLinx Multimedia Systems"}
{0x000514, "KDT Systems Co."}
{0x000515, "Nuark Co."}
{0x000516, "Smart Modular Technologies"}
{0x000517, "Shellcomm"}
{0x000518, "Jupiters Technology"}
{0x000519, "Siemens Building Technologies AG,"}
{0x00051a, "3Com Europe"}
{0x00051b, "Magic Control Technology"}
{0x00051c, "Xnet Technology"}
{0x00051d, "Airocon"}
{0x00051e, "Brocade Communications Systems"}
{0x00051f, "Taijin Media Co."}
{0x000520, "Smartronix"}
{0x000521, "Control Microsystems"}
{0x000522, "LEA*D"}
{0x000523, "AVL List GmbH"}
{0x000524, "BTL System (HK) Limited"}
{0x000525, "Puretek Industrial Co."}
{0x000526, "Ipas Gmbh"}
{0x000527, "SJ Tek Co."}
{0x000528, "New Focus"}
{0x000529, "Shanghai Broadan Communication Technology Co."}
{0x00052a, "Ikegami Tsushinki Co."}
{0x00052b, "Horiba"}
{0x00052c, "Supreme Magic"}
{0x00052d, "Zoltrix International Limited"}
{0x00052e, "Cinta Networks"}
{0x00052f, "Leviton Network Solutions"}
{0x000530, "Andiamo Systems"}
{0x000531, "Cisco Systems"}
{0x000532, "Cisco Systems"}
{0x000533, "Brocade Communications Systems"}
{0x000534, "Northstar Engineering"}
{0x000535, "Chip PC"}
{0x000536, "Danam Communications"}
{0x000537, "Nets Technology Co."}
{0x000538, "Merilus"}
{0x000539, "A Brand New World in Sweden AB"}
{0x00053a, "Willowglen Services Pte"}
{0x00053b, "Harbour Networks, Co. Beijing"}
{0x00053c, "Xircom"}
{0x00053d, "Agere Systems"}
{0x00053e, "KID Systeme GmbH"}
{0x00053f, "VisionTek"}
{0x000540, "Fast"}
{0x000541, "Advanced Systems Co."}
{0x000542, "Otari"}
{0x000543, "IQ Wireless GmbH"}
{0x000544, "Valley Technologies"}
{0x000545, "Internet Photonics"}
{0x000546, "Kddi Network & Solultions"}
{0x000547, "Starent Networks"}
{0x000548, "Disco"}
{0x000549, "Salira Optical Network Systems"}
{0x00054a, "Ario Data Networks"}
{0x00054b, "Eaton Automation AG"}
{0x00054c, "RF Innovations"}
{0x00054d, "Brans Technologies"}
{0x00054e, "Philips"}
{0x00054f, "Private"}
{0x000550, "Vcomms Connect Limited"}
{0x000551, "F & S Elektronik Systeme GmbH"}
{0x000552, "Xycotec Computer GmbH"}
{0x000553, "DVC Company"}
{0x000554, "Rangestar Wireless"}
{0x000555, "Japan Cash Machine Co."}
{0x000556, "360 Systems"}
{0x000557, "Agile TV"}
{0x000558, "Synchronous"}
{0x000559, "Intracom S.A."}
{0x00055a, "Power Dsine"}
{0x00055b, "Charles Industries"}
{0x00055c, "Kowa Company"}
{0x00055d, "D-Link Systems"}
{0x00055e, "Cisco Systems"}
{0x00055f, "Cisco Systems"}
{0x000560, "Leader Comm.co."}
{0x000561, "nac Image Technology"}
{0x000562, "Digital View Limited"}
{0x000563, "J-Works"}
{0x000564, "Tsinghua Bitway Co."}
{0x000565, "Tailyn Communication Company"}
{0x000566, "Secui.com"}
{0x000567, "Etymonic Design"}
{0x000568, "Piltofish Networks AB"}
{0x000569, "VMware"}
{0x00056a, "Heuft Systemtechnik GmbH"}
{0x00056b, "C.P. Technology Co."}
{0x00056c, "Hung Chang Co."}
{0x00056d, "Pacific"}
{0x00056e, "National Enhance Technology"}
{0x00056f, "Innomedia Technologies Pvt."}
{0x000570, "Baydel"}
{0x000571, "Seiwa Electronics Co."}
{0x000572, "Deonet Co."}
{0x000573, "Cisco Systems"}
{0x000574, "Cisco Systems"}
{0x000575, "CDS-Electronics BV"}
{0x000576, "NSM Technology"}
{0x000577, "SM Information & Communication"}
{0x000578, "Private"}
{0x000579, "Universal Control Solution"}
{0x00057a, "Overture Networks"}
{0x00057b, "Chung Nam Electronic Co."}
{0x00057c, "RCO Security AB"}
{0x00057d, "Sun Communications"}
{0x00057e, "Eckelmann Steuerungstechnik GmbH"}
{0x00057f, "Acqis Technology"}
{0x000580, "Fibrolan"}
{0x000581, "Snell"}
{0x000582, "ClearCube Technology"}
{0x000583, "ImageCom Limited"}
{0x000584, "AbsoluteValue Systems"}
{0x000585, "Juniper Networks"}
{0x000586, "Lucent Technologies"}
{0x000587, "Locus, Incorporated"}
{0x000588, "Sensoria"}
{0x000589, "National Datacomputer"}
{0x00058a, "Netcom Co."}
{0x00058b, "IPmental"}
{0x00058c, "Opentech"}
{0x00058d, "Lynx Photonic Networks"}
{0x00058e, "Flextronics International GmbH & Co. Nfg. KG"}
{0x00058f, "CLCsoft co."}
{0x000590, "Swissvoice"}
{0x000591, "Active Silicon"}
{0x000592, "Pultek"}
{0x000593, "Grammar Engine"}
{0x000594, "Ixxat Automation Gmbh"}
{0x000595, "Alesis"}
{0x000596, "Genotech Co."}
{0x000597, "Eagle Traffic Control Systems"}
{0x000598, "Cronos S.r.l."}
{0x000599, "DRS Test and Energy Management or DRS-TEM"}
{0x00059a, "Cisco Systems"}
{0x00059b, "Cisco Systems"}
{0x00059c, "Kleinknecht GmbH, Ing. Buero"}
{0x00059d, "Daniel Computing Systems"}
{0x00059e, "Zinwell"}
{0x00059f, "Yotta Networks"}
{0x0005a0, "Mobiline Kft."}
{0x0005a1, "Zenocom"}
{0x0005a2, "Celox Networks"}
{0x0005a3, "QEI"}
{0x0005a4, "Lucid Voice"}
{0x0005a5, "Kott"}
{0x0005a6, "Extron Electronics"}
{0x0005a7, "Hyperchip"}
{0x0005a8, "Wyle Electronics"}
{0x0005a9, "Princeton Networks"}
{0x0005aa, "Moore Industries International"}
{0x0005ab, "Cyber Fone"}
{0x0005ac, "Northern Digital"}
{0x0005ad, "Topspin Communications"}
{0x0005ae, "Mediaport USA"}
{0x0005af, "InnoScan Computing A/S"}
{0x0005b0, "Korea Computer Technology Co."}
{0x0005b1, "ASB Technology BV"}
{0x0005b2, "Medison Co."}
{0x0005b3, "Asahi-Engineering Co."}
{0x0005b4, "Aceex"}
{0x0005b5, "Broadcom Technologies"}
{0x0005b6, "Insys Microelectronics Gmbh"}
{0x0005b7, "Arbor Technology"}
{0x0005b8, "Electronic Design Associates"}
{0x0005b9, "Airvana"}
{0x0005ba, "Area Netwoeks"}
{0x0005bb, "Myspace AB"}
{0x0005bc, "Resorsys"}
{0x0005bd, "Roax BV"}
{0x0005be, "Kongsberg Seatex AS"}
{0x0005bf, "JustEzy Technology"}
{0x0005c0, "Digital Network Alacarte Co."}
{0x0005c1, "A-Kyung Motion"}
{0x0005c2, "Soronti"}
{0x0005c3, "Pacific Instruments"}
{0x0005c4, "Telect"}
{0x0005c5, "Flaga HF"}
{0x0005c6, "Triz Communications"}
{0x0005c7, "I/f-com A/S"}
{0x0005c8, "Verytech"}
{0x0005c9, "LG Innotek Co."}
{0x0005ca, "Hitron Technology"}
{0x0005cb, "Rois Technologies"}
{0x0005cc, "Sumtel Communications"}
{0x0005cd, "Denon"}
{0x0005ce, "Prolink Microsystems"}
{0x0005cf, "Thunder River Technologies"}
{0x0005d0, "Solinet Systems"}
{0x0005d1, "Metavector Technologies"}
{0x0005d2, "DAP Technologies"}
{0x0005d3, "eProduction Solutions"}
{0x0005d4, "FutureSmart Networks"}
{0x0005d5, "Speedcom Wireless"}
{0x0005d6, "Titan Wireless"}
{0x0005d7, "Vista Imaging"}
{0x0005d8, "Arescom"}
{0x0005d9, "Techno Valley"}
{0x0005da, "Apex Automationstechnik"}
{0x0005db, "PSI Nentec GmbH"}
{0x0005dc, "Cisco Systems"}
{0x0005dd, "Cisco Systems"}
{0x0005de, "Gi Fone Korea"}
{0x0005df, "Electronic Innovation"}
{0x0005e0, "Empirix"}
{0x0005e1, "Trellis Photonics"}
{0x0005e2, "Creativ Network Technologies"}
{0x0005e3, "LightSand Communications"}
{0x0005e4, "Red Lion Controls"}
{0x0005e5, "Renishaw PLC"}
{0x0005e6, "Egenera"}
{0x0005e7, "Netrake an AudioCodes Company"}
{0x0005e8, "TurboWave"}
{0x0005e9, "Unicess Network"}
{0x0005ea, "Rednix"}
{0x0005eb, "Blue Ridge Networks"}
{0x0005ec, "Mosaic Systems"}
{0x0005ed, "Technikum Joanneum GmbH"}
{0x0005ee, "Bewator Group"}
{0x0005ef, "Adoir Digital Technology"}
{0x0005f0, "Satec"}
{0x0005f1, "Vrcom"}
{0x0005f2, "Power"}
{0x0005f3, "Weboyn"}
{0x0005f4, "System Base Co."}
{0x0005f5, "OYO Geospace"}
{0x0005f6, "Young Chang Co."}
{0x0005f7, "Analog Devices"}
{0x0005f8, "Real Time Access"}
{0x0005f9, "TOA"}
{0x0005fa, "IPOptical"}
{0x0005fb, "ShareGate"}
{0x0005fc, "Schenck Pegasus"}
{0x0005fd, "PacketLight Networks"}
{0x0005fe, "Traficon N.V."}
{0x0005ff, "SNS Solutions"}
{0x000600, "Toshiba Teli"}
{0x000601, "Otanikeiki Co."}
{0x000602, "Cirkitech Electronics Co."}
{0x000603, "Baker Hughes"}
{0x000604, "@Track Communications"}
{0x000605, "Inncom International"}
{0x000606, "RapidWAN"}
{0x000607, "Omni Directional Control Technology"}
{0x000608, "At-Sky SAS"}
{0x000609, "Crossport Systems"}
{0x00060a, "Blue2space"}
{0x00060b, "Emerson Network Power"}
{0x00060c, "Melco Industries"}
{0x00060d, "Wave7 Optics"}
{0x00060e, "Igys Systems"}
{0x00060f, "Narad Networks"}
{0x000610, "Abeona Networks"}
{0x000611, "Zeus Wireless"}
{0x000612, "Accusys"}
{0x000613, "Kawasaki Microelectronics Incorporated"}
{0x000614, "Prism Holdings"}
{0x000615, "Kimoto Electric Co."}
{0x000616, "Tel Net Co."}
{0x000617, "Redswitch"}
{0x000618, "DigiPower Manufacturing"}
{0x000619, "Connection Technology Systems"}
{0x00061a, "Zetari"}
{0x00061b, "Notebook Development Lab.  Lenovo Japan"}
{0x00061c, "Hoshino Metal Industries"}
{0x00061d, "MIP Telecom"}
{0x00061e, "Maxan Systems"}
{0x00061f, "Vision Components GmbH"}
{0x000620, "Serial System"}
{0x000621, "Hinox, Co."}
{0x000622, "Chung Fu Chen Yeh Enterprise"}
{0x000623, "MGE UPS Systems France"}
{0x000624, "Gentner Communications"}
{0x000625, "The Linksys Group"}
{0x000626, "MWE GmbH"}
{0x000627, "Uniwide Technologies"}
{0x000628, "Cisco Systems"}
{0x000629, "IBM"}
{0x00062a, "Cisco Systems"}
{0x00062b, "Intraserver Technology"}
{0x00062c, "Bivio Networks"}
{0x00062d, "TouchStar Technologies, L.L.C."}
{0x00062e, "Aristos Logic"}
{0x00062f, "Pivotech Systems"}
{0x000630, "Adtranz Sweden"}
{0x000631, "Optical Solutions"}
{0x000632, "Mesco Engineering GmbH"}
{0x000633, "Cross Match Technologies GmbH"}
{0x000634, "GTE Airfone"}
{0x000635, "PacketAir Networks"}
{0x000636, "Jedai Broadband Networks"}
{0x000637, "Toptrend-Meta Information (ShenZhen)"}
{0x000638, "Sungjin C&C Co."}
{0x000639, "Newtec"}
{0x00063a, "Dura Micro"}
{0x00063b, "Arcturus Networks"}
{0x00063c, "Intrinsyc Europe"}
{0x00063d, "Microwave Data Systems"}
{0x00063e, "Opthos"}
{0x00063f, "Everex Communications"}
{0x000640, "White Rock Networks"}
{0x000641, "Itcn"}
{0x000642, "Genetel Systems"}
{0x000643, "Sono Computer Co."}
{0x000644, "Neix"}
{0x000645, "Meisei Electric Co."}
{0x000646, "ShenZhen XunBao Network Technology Co"}
{0x000647, "Etrali S.A."}
{0x000648, "Seedsware"}
{0x000649, "3M Deutschland GmbH"}
{0x00064a, "Honeywell Co., (korea)"}
{0x00064b, "Alexon Co."}
{0x00064c, "Invicta Networks"}
{0x00064d, "Sencore"}
{0x00064e, "Broad Net Technology"}
{0x00064f, "Pro-nets Technology"}
{0x000650, "Tiburon Networks"}
{0x000651, "Aspen Networks"}
{0x000652, "Cisco Systems"}
{0x000653, "Cisco Systems"}
{0x000654, "Winpresa Building Automation Technologies GmbH"}
{0x000655, "Yipee"}
{0x000656, "Tactel AB"}
{0x000657, "Market Central"}
{0x000658, "Helmut Fischer GmbH Institut fr Elektronik und Messtechnik"}
{0x000659, "EAL (Apeldoorn) B.V."}
{0x00065a, "Strix Systems"}
{0x00065b, "Dell Computer"}
{0x00065c, "Malachite Technologies"}
{0x00065d, "Heidelberg Web Systems"}
{0x00065e, "Photuris"}
{0x00065f, "ECI Telecom - Ngts"}
{0x000660, "Nadex Co."}
{0x000661, "NIA Home Technologies"}
{0x000662, "MBM Technology"}
{0x000663, "Human Technology Co."}
{0x000664, "Fostex"}
{0x000665, "Sunny Giken"}
{0x000666, "Roving Networks"}
{0x000667, "Tripp Lite"}
{0x000668, "Vicon Industries"}
{0x000669, "Datasound Laboratories"}
{0x00066a, "InfiniCon Systems"}
{0x00066b, "Sysmex"}
{0x00066c, "Robinson"}
{0x00066d, "Compuprint S.P.A."}
{0x00066e, "Delta Electronics"}
{0x00066f, "Korea Data Systems"}
{0x000670, "Upponetti Oy"}
{0x000671, "Softing AG"}
{0x000672, "Netezza"}
{0x000673, "TKH Security Solutions USA"}
{0x000674, "Spectrum Control"}
{0x000675, "Banderacom"}
{0x000676, "Novra Technologies"}
{0x000677, "Sick AG"}
{0x000678, "Marantz Brand Company"}
{0x000679, "Konami"}
{0x00067a, "JMP Systems"}
{0x00067b, "Toplink C&C"}
{0x00067c, "Cisco Systems"}
{0x00067d, "Takasago"}
{0x00067e, "WinCom Systems"}
{0x00067f, "Digeo"}
{0x000680, "Card Access"}
{0x000681, "Goepel Electronic GmbH"}
{0x000682, "Convedia"}
{0x000683, "Bravara Communications"}
{0x000684, "Biacore AB"}
{0x000685, "NetNearU"}
{0x000686, "Zardcom Co."}
{0x000687, "Omnitron Systems Technology"}
{0x000688, "Telways Communication Co."}
{0x000689, "yLez Technologies Pte"}
{0x00068a, "NeuronNet Co. R&D Center"}
{0x00068b, "AirRunner Technologies"}
{0x00068c, "3Com"}
{0x00068d, "Sepaton"}
{0x00068e, "HID"}
{0x00068f, "Telemonitor"}
{0x000690, "Euracom Communication GmbH"}
{0x000691, "PT Inovacao"}
{0x000692, "Intruvert Networks"}
{0x000693, "Flexus Computer Technology"}
{0x000694, "Mobillian"}
{0x000695, "Ensure Technologies"}
{0x000696, "Advent Networks"}
{0x000697, "R & D Center"}
{0x000698, "egnite Software GmbH"}
{0x000699, "Vida Design Co."}
{0x00069a, "e & Tel"}
{0x00069b, "AVT Audio Video Technologies GmbH"}
{0x00069c, "Transmode Systems AB"}
{0x00069d, "Petards"}
{0x00069e, "Uniqa"}
{0x00069f, "Kuokoa Networks"}
{0x0006a0, "Mx Imaging"}
{0x0006a1, "Celsian Technologies"}
{0x0006a2, "Microtune"}
{0x0006a3, "Bitran"}
{0x0006a4, "Innowell"}
{0x0006a5, "Pinon"}
{0x0006a6, "Artistic Licence (UK)"}
{0x0006a7, "Primarion"}
{0x0006a8, "KC Technology"}
{0x0006a9, "Universal Instruments"}
{0x0006aa, "VT Miltope"}
{0x0006ab, "W-Link Systems"}
{0x0006ac, "Intersoft Co."}
{0x0006ad, "KB Electronics"}
{0x0006ae, "Himachal Futuristic Communications"}
{0x0006af, "Xalted Networks"}
{0x0006b0, "Comtech EF Data"}
{0x0006b1, "Sonicwall"}
{0x0006b2, "Linxtek Co."}
{0x0006b3, "Diagraph"}
{0x0006b4, "Vorne Industries"}
{0x0006b5, "Source Photonics"}
{0x0006b6, "Nir-Or Israel"}
{0x0006b7, "Telem Gmbh"}
{0x0006b8, "Bandspeed"}
{0x0006b9, "A5TEK"}
{0x0006ba, "Westwave Communications"}
{0x0006bb, "ATI Technologies"}
{0x0006bc, "Macrolink"}
{0x0006bd, "Bntechnology Co."}
{0x0006be, "Baumer Optronic GmbH"}
{0x0006bf, "Accella Technologies Co."}
{0x0006c0, "United Internetworks"}
{0x0006c1, "Cisco Systems"}
{0x0006c2, "Smartmatic"}
{0x0006c3, "Schindler Elevator"}
{0x0006c4, "Piolink"}
{0x0006c5, "Innovi Technologies Limited"}
{0x0006c6, "lesswire AG"}
{0x0006c7, "Rfnet Technologies Pte (S)"}
{0x0006c8, "Sumitomo Metal Micro Devices"}
{0x0006c9, "Technical Marketing Research"}
{0x0006ca, "American Computer & Digital Components, (acdc)"}
{0x0006cb, "Jotron Electronics A/S"}
{0x0006cc, "JMI Electronics Co."}
{0x0006cd, "Leaf Imaging"}
{0x0006ce, "Dateno"}
{0x0006cf, "Thales Avionics In-Flight Systems"}
{0x0006d0, "Elgar Electronics"}
{0x0006d1, "Tahoe Networks"}
{0x0006d2, "Tundra Semiconductor"}
{0x0006d3, "Alpha Telecom, U.S.A."}
{0x0006d4, "Interactive Objects"}
{0x0006d5, "Diamond Systems"}
{0x0006d6, "Cisco Systems"}
{0x0006d7, "Cisco Systems"}
{0x0006d8, "Maple Optical Systems"}
{0x0006d9, "IPM-Net S.p.A."}
{0x0006da, "Itran Communications"}
{0x0006db, "Ichips Co."}
{0x0006dc, "Syabas Technology (Amquest)"}
{0x0006dd, "AT & T Laboratories - Cambridge"}
{0x0006de, "Flash Technology"}
{0x0006df, "Aidonic"}
{0x0006e0, "MAT Co."}
{0x0006e1, "Techno Trade s.a"}
{0x0006e2, "Ceemax Technology Co."}
{0x0006e3, "Quantitative Imaging"}
{0x0006e4, "Citel Technologies"}
{0x0006e5, "Fujian Newland Computer Co."}
{0x0006e6, "DongYang Telecom Co."}
{0x0006e7, "Bit Blitz Communications"}
{0x0006e8, "Optical Network Testing"}
{0x0006e9, "Intime"}
{0x0006ea, "Elzet80 Mikrocomputer Gmbh&co. KG"}
{0x0006eb, "Global Data"}
{0x0006ec, "Harris"}
{0x0006ed, "Inara Networks"}
{0x0006ee, "Shenyang Neu-era Information & Technology Stock Co."}
{0x0006ef, "Maxxan Systems"}
{0x0006f0, "Digeo"}
{0x0006f1, "Optillion"}
{0x0006f2, "Platys Communications"}
{0x0006f3, "AcceLight Networks"}
{0x0006f4, "Prime Electronics & Satellitics"}
{0x0006f5, "Alps Co"}
{0x0006f6, "Cisco Systems"}
{0x0006f7, "Alps Electric Co"}
{0x0006f8, "CPU Technology"}
{0x0006f9, "Mitsui Zosen Systems Research"}
{0x0006fa, "IP Square Co"}
{0x0006fb, "Hitachi Printing Solutions"}
{0x0006fc, "Fnet Co."}
{0x0006fd, "Comjet Information Systems"}
{0x0006fe, "Ambrado"}
{0x0006ff, "Sheba Systems Co."}
{0x000700, "Zettamedia Korea"}
{0x000701, "Racal-datacom"}
{0x000702, "Varian Medical Systems"}
{0x000703, "Csee Transport"}
{0x000704, "Alps Electric Co"}
{0x000705, "Endress & Hauser GmbH & Co"}
{0x000706, "Sanritz"}
{0x000707, "Interalia"}
{0x000708, "Bitrage"}
{0x000709, "Westerstrand Urfabrik AB"}
{0x00070a, "Unicom Automation Co."}
{0x00070b, "Novabase SGPS"}
{0x00070c, "SVA-Intrusion.com Co."}
{0x00070d, "Cisco Systems"}
{0x00070e, "Cisco Systems"}
{0x00070f, "Fujant"}
{0x000710, "Adax"}
{0x000711, "Acterna"}
{0x000712, "JAL Information Technology"}
{0x000713, "IP One"}
{0x000714, "Brightcom"}
{0x000715, "General Research of Electronics"}
{0x000716, "J & S Marine"}
{0x000717, "Wieland Electric GmbH"}
{0x000718, "iCanTek Co."}
{0x000719, "Mobiis Co."}
{0x00071a, "Finedigital"}
{0x00071b, "CDV Americas"}
{0x00071c, "AT&T Fixed Wireless Services"}
{0x00071d, "Satelsa Sistemas Y Aplicaciones De Telecomunicaciones"}
{0x00071e, "Tri-M Engineering / Nupak Dev."}
{0x00071f, "European Systems Integration"}
{0x000720, "Trutzschler GmbH & Co. KG"}
{0x000721, "Formac Elektronik GmbH"}
{0x000722, "The Nielsen Company"}
{0x000723, "Elcon Systemtechnik Gmbh"}
{0x000724, "Telemax Co."}
{0x000725, "Bematech International"}
{0x000726, "Shenzhen Gongjin Electronics Co."}
{0x000727, "Zi (HK)"}
{0x000728, "Neo Telecom"}
{0x000729, "Kistler Instrumente AG"}
{0x00072a, "Innovance Networks"}
{0x00072b, "Jung Myung Telecom Co."}
{0x00072c, "Fabricom"}
{0x00072d, "CNSystems"}
{0x00072e, "North Node AB"}
{0x00072f, "Intransa"}
{0x000730, "Hutchison Optel Telecom Technology Co."}
{0x000731, "Ophir-Spiricon"}
{0x000732, "Aaeon Technology"}
{0x000733, "Dancontrol Engineering"}
{0x000734, "ONStor"}
{0x000735, "Flarion Technologies"}
{0x000736, "Data Video Technologies Co."}
{0x000737, "Soriya Co."}
{0x000738, "Young Technology Co."}
{0x000739, "Scotty Group Austria Gmbh"}
{0x00073a, "Inventel Systemes"}
{0x00073b, "Tenovis GmbH & Co KG"}
{0x00073c, "Telecom Design"}
{0x00073d, "Nanjing Postel Telecommunications Co."}
{0x00073e, "China Great-Wall Computer Shenzhen Co."}
{0x00073f, "Woojyun Systec Co."}
{0x000740, "Buffalo"}
{0x000741, "Sierra Automated Systems"}
{0x000742, "Current Technologies"}
{0x000743, "Chelsio Communications"}
{0x000744, "Unico"}
{0x000745, "Radlan Computer Communications"}
{0x000746, "Turck"}
{0x000747, "Mecalc"}
{0x000748, "The Imaging Source Europe"}
{0x000749, "CENiX"}
{0x00074a, "Carl Valentin GmbH"}
{0x00074b, "Daihen"}
{0x00074c, "Beicom"}
{0x00074d, "Zebra Technologies"}
{0x00074e, "Naughty boy co."}
{0x00074f, "Cisco Systems"}
{0x000750, "Cisco Systems"}
{0x000751, "m-u-t AG"}
{0x000752, "Rhythm Watch Co."}
{0x000753, "Beijing Qxcomm Technology Co."}
{0x000754, "Xyterra Computing"}
{0x000755, "Lafon SA"}
{0x000756, "Juyoung Telecom"}
{0x000757, "Topcall International AG"}
{0x000758, "Dragonwave"}
{0x000759, "Boris Manufacturing"}
{0x00075a, "Air Products and Chemicals"}
{0x00075b, "Gibson Guitars"}
{0x00075c, "Eastman Kodak Company"}
{0x00075d, "Celleritas"}
{0x00075e, "Ametek Power Instruments"}
{0x00075f, "VCS Video Communication Systems AG"}
{0x000760, "Tomis Information & Telecom"}
{0x000761, "Logitech SA"}
{0x000762, "Group Sense Limited"}
{0x000763, "Sunniwell Cyber Tech. Co."}
{0x000764, "YoungWoo Telecom Co."}
{0x000765, "Jade Quantum Technologies"}
{0x000766, "Chou Chin Industrial Co."}
{0x000767, "Yuxing Electronics Company Limited"}
{0x000768, "Danfoss A/S"}
{0x000769, "Italiana Macchi SpA"}
{0x00076a, "Nexteye Co."}
{0x00076b, "Stralfors AB"}
{0x00076c, "Daehanet"}
{0x00076d, "Flexlight Networks"}
{0x00076e, "Sinetica Limited"}
{0x00076f, "Synoptics Limited"}
{0x000770, "Locusnetworks"}
{0x000771, "Embedded System"}
{0x000772, "Alcatel Shanghai Bell Co."}
{0x000773, "Ascom Powerline Communications"}
{0x000774, "GuangZhou Thinker Technology Co."}
{0x000775, "Valence Semiconductor"}
{0x000776, "Federal APD"}
{0x000777, "Motah"}
{0x000778, "Gerstel Gmbh & Co. KG"}
{0x000779, "Sungil Telecom Co."}
{0x00077a, "Infoware System Co."}
{0x00077b, "Millimetrix Broadband Networks"}
{0x00077c, "Westermo Teleindustri AB"}
{0x00077d, "Cisco Systems"}
{0x00077e, "Elrest GmbH"}
{0x00077f, "J Communications Co."}
{0x000780, "Bluegiga Technologies OY"}
{0x000781, "Itron"}
{0x000782, "Oracle"}
{0x000783, "SynCom Network"}
{0x000784, "Cisco Systems"}
{0x000785, "Cisco Systems"}
{0x000786, "Wireless Networks"}
{0x000787, "Idea System Co."}
{0x000788, "Clipcomm"}
{0x000789, "Dongwon Systems"}
{0x00078a, "Mentor Data System"}
{0x00078b, "Wegener Communications"}
{0x00078c, "Elektronikspecialisten i Borlange AB"}
{0x00078d, "NetEngines"}
{0x00078e, "Garz & Friche GmbH"}
{0x00078f, "Emkay Innovative Products"}
{0x000790, "Tri-M Technologies (s) Limited"}
{0x000791, "International Data Communications"}
{0x000792, "Suetron Electronic GmbH"}
{0x000793, "Shin Satellite Public Company Limited"}
{0x000794, "Simple Devices"}
{0x000795, "Elitegroup Computer System Co. (ECS)"}
{0x000796, "LSI Systems"}
{0x000797, "Netpower Co."}
{0x000798, "Selea SRL"}
{0x000799, "Tipping Point Technologies"}
{0x00079a, "Verint Systems"}
{0x00079b, "Aurora Networks"}
{0x00079c, "Golden Electronics Technology Co."}
{0x00079d, "Musashi Co."}
{0x00079e, "Ilinx Co."}
{0x00079f, "Action Digital"}
{0x0007a0, "e-Watch"}
{0x0007a1, "Viasys Healthcare Gmbh"}
{0x0007a2, "Opteon"}
{0x0007a3, "Ositis Software"}
{0x0007a4, "GN Netcom"}
{0x0007a5, "Y.D.K Co."}
{0x0007a6, "Home Automation"}
{0x0007a7, "A-Z"}
{0x0007a8, "Haier Group Technologies"}
{0x0007a9, "Novasonics"}
{0x0007aa, "Quantum Data"}
{0x0007ab, "Samsung Electronics Co."}
{0x0007ac, "Eolring"}
{0x0007ad, "Pentacon GmbH Foto-und Feinwerktechnik"}
{0x0007ae, "Britestream Networks"}
{0x0007af, "N-tron"}
{0x0007b0, "Office Details"}
{0x0007b1, "Equator Technologies"}
{0x0007b2, "Transaccess S.A."}
{0x0007b3, "Cisco Systems"}
{0x0007b4, "Cisco Systems"}
{0x0007b5, "Any One Wireless"}
{0x0007b6, "Telecom Technology"}
{0x0007b7, "Samurai Ind. Prods Eletronicos Ltda"}
{0x0007b8, "Corvalent"}
{0x0007b9, "Ginganet"}
{0x0007ba, "UTStarcom"}
{0x0007bb, "Candera"}
{0x0007bc, "Identix"}
{0x0007bd, "Radionet"}
{0x0007be, "DataLogic SpA"}
{0x0007bf, "Armillaire Technologies"}
{0x0007c0, "NetZerver"}
{0x0007c1, "Overture Networks"}
{0x0007c2, "Netsys Telecom"}
{0x0007c3, "Thomson"}
{0x0007c4, "Jean Co."}
{0x0007c5, "Gcom"}
{0x0007c6, "VDS Vosskuhler GmbH"}
{0x0007c7, "Synectics Systems Limited"}
{0x0007c8, "Brain21"}
{0x0007c9, "Technol Seven Co."}
{0x0007ca, "Creatix Polymedia Ges Fur Kommunikaitonssysteme"}
{0x0007cb, "Freebox SA"}
{0x0007cc, "Kaba Benzing GmbH"}
{0x0007cd, "Nmtel Co."}
{0x0007ce, "Cabletime Limited"}
{0x0007cf, "Anoto AB"}
{0x0007d0, "Automat Engenharia de Automaoa Ltda."}
{0x0007d1, "Spectrum Signal Processing"}
{0x0007d2, "Logopak Systeme"}
{0x0007d3, "Stork Prints B.V. "}
{0x0007d4, "Zhejiang Yutong Network Communication Co"}
{0x0007d5, "3e Technologies Int;."}
{0x0007d6, "Commil"}
{0x0007d7, "Caporis Networks AG"}
{0x0007d8, "Hitron Systems"}
{0x0007d9, "Splicecom"}
{0x0007da, "Neuro Telecom Co."}
{0x0007db, "Kirana Networks"}
{0x0007dc, "Atek Co"}
{0x0007dd, "Cradle Technologies"}
{0x0007de, "eCopilt AB"}
{0x0007df, "Vbrick Systems"}
{0x0007e0, "Palm"}
{0x0007e1, "WIS Communications Co."}
{0x0007e2, "Bitworks"}
{0x0007e3, "Navcom Technology"}
{0x0007e4, "SoftRadio Co."}
{0x0007e5, "Coup"}
{0x0007e6, "edgeflow Canada"}
{0x0007e7, "FreeWave Technologies"}
{0x0007e8, "EdgeWave"}
{0x0007e9, "Intel"}
{0x0007ea, "Massana"}
{0x0007eb, "Cisco Systems"}
{0x0007ec, "Cisco Systems"}
{0x0007ed, "Altera"}
{0x0007ee, "telco Informationssysteme GmbH"}
{0x0007ef, "Lockheed Martin Tactical Systems"}
{0x0007f0, "LogiSync"}
{0x0007f1, "TeraBurst Networks"}
{0x0007f2, "IOA"}
{0x0007f3, "Thinkengine Networks"}
{0x0007f4, "Eletex Co."}
{0x0007f5, "Bridgeco Co AG"}
{0x0007f6, "Qqest Software Systems"}
{0x0007f7, "Galtronics"}
{0x0007f8, "ITDevices"}
{0x0007f9, "Phonetics"}
{0x0007fa, "ITT Co."}
{0x0007fb, "Giga Stream Umts Technologies Gmbh"}
{0x0007fc, "Adept Systems"}
{0x0007fd, "LANergy"}
{0x0007fe, "Rigaku"}
{0x0007ff, "Gluon Networks"}
{0x000800, "Multitech Systems"}
{0x000801, "HighSpeed Surfing"}
{0x000802, "Hewlett-Packard Company"}
{0x000803, "Cos Tron"}
{0x000804, "ICA"}
{0x000805, "Techno-Holon"}
{0x000806, "Raonet Systems"}
{0x000807, "Access Devices Limited"}
{0x000808, "PPT Vision"}
{0x000809, "Systemonic AG"}
{0x00080a, "Espera-Werke GmbH"}
{0x00080b, "Birka BPA Informationssystem AB"}
{0x00080c, "VDA Elettronica spa"}
{0x00080d, "Toshiba"}
{0x00080e, "Motorola Mobility"}
{0x00080f, "Proximion Fiber Optics AB"}
{0x000810, "Key Technology"}
{0x000811, "Voix"}
{0x000812, "GM-2"}
{0x000813, "Diskbank"}
{0x000814, "TIL Technologies"}
{0x000815, "Cats Co."}
{0x000816, "Bluetags A/S"}
{0x000817, "EmergeCore Networks"}
{0x000818, "Pixelworks"}
{0x000819, "Banksys"}
{0x00081a, "Sanrad Intelligence Storage Communications (2000)"}
{0x00081b, "Windigo Systems"}
{0x00081c, "@pos.com"}
{0x00081d, "Ipsil, Incorporated"}
{0x00081e, "Repeatit AB"}
{0x00081f, "Pou Yuen Tech"}
{0x000820, "Cisco Systems"}
{0x000821, "Cisco Systems"}
{0x000822, "InPro Comm"}
{0x000823, "Texa"}
{0x000824, "Copitrak"}
{0x000825, "Acme Packet"}
{0x000826, "Colorado Med Tech"}
{0x000827, "ADB Broadband Italia"}
{0x000828, "Koei Engineering"}
{0x000829, "Aval Nagasaki"}
{0x00082a, "Powerwallz Network Security"}
{0x00082b, "Wooksung Electronics"}
{0x00082c, "Homag AG"}
{0x00082d, "Indus Teqsite Private Limited"}
{0x00082e, "Multitone Electronics PLC"}
{0x00082f, "Cisco Systems"}
{0x000830, "Cisco Systems"}
{0x000831, "Cisco Systems"}
{0x00084e, "DivergeNet"}
{0x00084f, "Qualstar"}
{0x000850, "Arizona Instrument"}
{0x000851, "Canadian Bank Note Company"}
{0x000852, "Davolink Co."}
{0x000853, "Schleicher GmbH & Co. Relaiswerke KG"}
{0x000854, "Netronix"}
{0x000855, "Nasa-goddard Space Flight Center"}
{0x000856, "Gamatronic Electronic Industries"}
{0x000857, "Polaris Networks"}
{0x000858, "Novatechnology"}
{0x000859, "ShenZhen Unitone Electronics Co."}
{0x00085a, "IntiGate"}
{0x00085b, "Hanbit Electronics Co."}
{0x00085c, "Shanghai Dare Technologies Co."}
{0x00085d, "Aastra"}
{0x00085e, "PCO AG"}
{0x00085f, "Picanol N.V."}
{0x000860, "LodgeNet Entertainment"}
{0x000861, "SoftEnergy Co."}
{0x000862, "NEC Eluminant Technologies"}
{0x000863, "Entrisphere"}
{0x000864, "Fasy S.p.A."}
{0x000865, "Jascom CO."}
{0x000866, "DSX Access Systems"}
{0x000867, "Uptime Devices"}
{0x000868, "PurOptix"}
{0x000869, "Command-e Technology Co."}
{0x00086a, "Securiton Gmbh"}
{0x00086b, "Mipsys"}
{0x00086c, "Plasmon LMS"}
{0x00086d, "Missouri FreeNet"}
{0x00086e, "Hyglo AB"}
{0x00086f, "Resources Computer Network"}
{0x000870, "Rasvia Systems"}
{0x000871, "Northdata Co."}
{0x000872, "Sorenson Communications"}
{0x000873, "DapTechnology B.V."}
{0x000874, "Dell Computer"}
{0x000875, "Acorp Electronics"}
{0x000876, "SDSystem"}
{0x000877, "Liebert-Hiross Spa"}
{0x000878, "Benchmark Storage Innovations"}
{0x000879, "CEM"}
{0x00087a, "Wipotec GmbH"}
{0x00087b, "RTX Telecom A/S"}
{0x00087c, "Cisco Systems"}
{0x00087d, "Cisco Systems"}
{0x00087e, "Bon Electro-Telecom"}
{0x00087f, "Spaun Electronic Gmbh & Co. KG"}
{0x000880, "BroadTel Canada Communications"}
{0x000881, "Digital Hands Co."}
{0x000882, "Sigma"}
{0x000883, "Hewlett-Packard Company"}
{0x000884, "Index Braille AB"}
{0x000885, "EMS Dr. Thomas Wuensche"}
{0x000886, "Hansung Teliann"}
{0x000887, "Maschinenfabrik Reinhausen GmbH"}
{0x000888, "Oullim Information Technology"}
{0x000889, "Echostar Technologies"}
{0x00088a, "Minds@Work"}
{0x00088b, "Tropic Networks"}
{0x00088c, "Quanta Network Systems"}
{0x00088d, "Sigma-Links"}
{0x00088e, "Nihon Computer Co."}
{0x00088f, "Advanced Digital Technology"}
{0x000890, "Avilinks SA"}
{0x000891, "Lyan"}
{0x000892, "EM Solutions"}
{0x000893, "LE Information Communication"}
{0x000894, "InnoVISION Multimedia"}
{0x000895, "Dirc Technologie Gmbh &KG"}
{0x000896, "Printronix"}
{0x000897, "Quake Technologies"}
{0x000898, "Gigabit Optics"}
{0x000899, "Netbind"}
{0x00089a, "Alcatel Microelectronics"}
{0x00089b, "ICP Electronics"}
{0x00089c, "Elecs Industry Co."}
{0x00089d, "UHD-Elektronik"}
{0x00089e, "Beijing Enter-NetLTD"}
{0x00089f, "EFM Networks"}
{0x0008a0, "Stotz Feinmesstechnik GmbH"}
{0x0008a1, "CNet Technology"}
{0x0008a2, "ADI Engineering"}
{0x0008a3, "Cisco Systems"}
{0x0008a4, "Cisco Systems"}
{0x0008a5, "Peninsula Systems"}
{0x0008a6, "Multiware & Image Co."}
{0x0008a7, "iLogic"}
{0x0008a8, "Systec Co."}
{0x0008a9, "SangSang Technology"}
{0x0008aa, "Karam"}
{0x0008ab, "EnerLinx.com"}
{0x0008ac, "Eltromat GmbH"}
{0x0008ad, "Toyo-Linx Co."}
{0x0008ae, "PacketFront International AB"}
{0x0008af, "Novatec"}
{0x0008b0, "BKtel communications GmbH"}
{0x0008b1, "ProQuent Systems"}
{0x0008b2, "Shenzhen Compass Technology Development Co."}
{0x0008b3, "Fastwel"}
{0x0008b4, "Syspol"}
{0x0008b5, "TAI Guen Enterprise CO."}
{0x0008b6, "RouteFree"}
{0x0008b7, "HIT Incorporated"}
{0x0008b8, "E.F. Johnson"}
{0x0008b9, "Kaon Media Co."}
{0x0008ba, "Erskine Systems"}
{0x0008bb, "NetExcell"}
{0x0008bc, "Ilevo AB"}
{0x0008bd, "Tepg-us"}
{0x0008be, "Xenpak MSA Group"}
{0x0008bf, "Aptus Elektronik AB"}
{0x0008c0, "ASA Systems"}
{0x0008c1, "Avistar Communications"}
{0x0008c2, "Cisco Systems"}
{0x0008c3, "Contex A/S"}
{0x0008c4, "Hikari Co."}
{0x0008c5, "Liontech Co."}
{0x0008c6, "Philips Consumer Communications"}
{0x0008c7, "Hewlett-Packard Company"}
{0x0008c8, "Soneticom"}
{0x0008c9, "TechniSat Digital GmbH"}
{0x0008ca, "TwinHan Technology Co."}
{0x0008cb, "Zeta Broadband"}
{0x0008cc, "Remotec"}
{0x0008cd, "With-Net"}
{0x0008ce, "IPMobileNet"}
{0x0008cf, "Nippon Koei Power Systems Co."}
{0x0008d0, "Musashi Engineering Co."}
{0x0008d1, "Karel"}
{0x0008d2, "Zoom Networks"}
{0x0008d3, "Hercules Technologies S.A."}
{0x0008d4, "IneoQuest Technologies"}
{0x0008d5, "Vanguard Networks Solutions"}
{0x0008d6, "Hassnet"}
{0x0008d7, "HOW"}
{0x0008d8, "Dowkey Microwave"}
{0x0008d9, "Mitadenshi Co."}
{0x0008da, "SofaWare Technologies"}
{0x0008db, "Corrigent Systems"}
{0x0008dc, "Wiznet"}
{0x0008dd, "Telena Communications"}
{0x0008de, "3UP Systems"}
{0x0008df, "Alistel"}
{0x0008e0, "ATO Technology"}
{0x0008e1, "Barix AG"}
{0x0008e2, "Cisco Systems"}
{0x0008e3, "Cisco Systems"}
{0x0008e4, "Envenergy"}
{0x0008e5, "IDK"}
{0x0008e6, "Littlefeet"}
{0x0008e7, "SHI ControlSystems"}
{0x0008e8, "Excel Master"}
{0x0008e9, "NextGig"}
{0x0008ea, "Motion Control Engineering"}
{0x0008eb, "Romwin Co."}
{0x0008ec, "Optical Zonu"}
{0x0008ed, "ST&T Instrument"}
{0x0008ee, "Logic Product Development"}
{0x0008ef, "Dibal"}
{0x0008f0, "Next Generation Systems"}
{0x0008f1, "Voltaire"}
{0x0008f2, "C&S Technology"}
{0x0008f3, "Wany"}
{0x0008f4, "Bluetake Technology Co."}
{0x0008f5, "Yestechnology Co."}
{0x0008f6, "Sumitomo Electric System Solutions Co."}
{0x0008f7, "Hitachi, Semiconductor &amp; Integrated Circuits Gr"}
{0x0008f8, "Guardall"}
{0x0008f9, "Emerson Network Power"}
{0x0008fa, "Karl E.Brinkmann GmbH"}
{0x0008fb, "SonoSite"}
{0x0008fc, "Gigaphoton"}
{0x0008fd, "BlueKorea Co."}
{0x0008fe, "Unik C&C Co."}
{0x0008ff, "Trilogy Communications"}
{0x000900, "TMT"}
{0x000901, "Shenzhen Shixuntong Information & Technoligy Co"}
{0x000902, "Redline Communications"}
{0x000903, "Panasas"}
{0x000904, "Mondial Electronic"}
{0x000905, "iTEC Technologies"}
{0x000906, "Esteem Networks"}
{0x000907, "Chrysalis Development"}
{0x000908, "VTech Technology"}
{0x000909, "Telenor Connect A/S"}
{0x00090a, "SnedFar Technology Co."}
{0x00090b, "MTL  Instruments PLC"}
{0x00090c, "Mayekawa Mfg. Co."}
{0x00090d, "Leader Electronics"}
{0x00090e, "Helix Technology"}
{0x00090f, "Fortinet"}
{0x000910, "Simple Access"}
{0x000911, "Cisco Systems"}
{0x000912, "Cisco Systems"}
{0x000913, "SystemK"}
{0x000914, "Computrols"}
{0x000915, "CAS"}
{0x000916, "Listman Home Technologies"}
{0x000917, "WEM Technology"}
{0x000918, "Samsung Techwin Co."}
{0x000919, "MDS Gateways"}
{0x00091a, "Macat Optics & Electronics Co."}
{0x00091b, "Digital Generation"}
{0x00091c, "CacheVision"}
{0x00091d, "Proteam Computer"}
{0x00091e, "Firstech Technology"}
{0x00091f, "A&amp;D Co."}
{0x000920, "Epox Computer Co."}
{0x000921, "Planmeca Oy"}
{0x000922, "TST Biometrics GmbH"}
{0x000923, "Heaman System Co."}
{0x000924, "Telebau GmbH"}
{0x000925, "VSN Systemen BV"}
{0x000926, "Yoda Communications"}
{0x000927, "Toyokeiki Co."}
{0x000928, "Telecore"}
{0x000929, "Sanyo Industries (UK) Limited"}
{0x00092a, "Mytecs Co."}
{0x00092b, "iQstor Networks"}
{0x00092c, "Hitpoint"}
{0x00092d, "HTC"}
{0x00092e, "B&Tech System"}
{0x00092f, "Akom Technology"}
{0x000930, "AeroConcierge"}
{0x000931, "Future Internet"}
{0x000932, "Omnilux"}
{0x000933, "OphitLtd."}
{0x000934, "Dream-Multimedia-Tv GmbH"}
{0x000935, "Sandvine Incorporated"}
{0x000936, "Ipetronik GmbH &KG"}
{0x000937, "Inventec Appliance"}
{0x000938, "Allot Communications"}
{0x000939, "ShibaSoku Co."}
{0x00093a, "Molex Fiber Optics"}
{0x00093b, "Hyundai Networks"}
{0x00093c, "Jacques Technologies P/L"}
{0x00093d, "Newisys"}
{0x00093e, "C&I Technologies"}
{0x00093f, "Double-Win Enterpirse CO."}
{0x000940, "Agfeo Gmbh & Co. KG"}
{0x000941, "Allied Telesis K.K."}
{0x000942, "Wireless Technologies"}
{0x000943, "Cisco Systems"}
{0x000944, "Cisco Systems"}
{0x000945, "Palmmicro Communications"}
{0x000946, "Cluster Labs GmbH"}
{0x000947, "Aztek"}
{0x000948, "Vista Control Systems"}
{0x000949, "Glyph Technologies"}
{0x00094a, "Homenet Communications"}
{0x00094b, "FillFactory NV"}
{0x00094c, "Communication Weaver Co."}
{0x00094d, "Braintree Communications"}
{0x00094e, "Bartech Systems International"}
{0x00094f, "elmegt GmbH & Co. KG"}
{0x000950, "Independent Storage"}
{0x000951, "Apogee Imaging Systems"}
{0x000952, "Auerswald GmbH & Co. KG"}
{0x000953, "Linkage System IntegrationLtd."}
{0x000954, "AMiT spol. s. r. o."}
{0x000955, "Young Generation International"}
{0x000956, "Network Systems Group, (NSG)"}
{0x000957, "Supercaller"}
{0x000958, "Intelnet S.A."}
{0x000959, "Sitecsoft"}
{0x00095a, "Racewood Technology"}
{0x00095b, "Netgear"}
{0x00095c, "Philips Medical Systems - Cardiac and Monitoring Systems (CM"}
{0x00095d, "Dialogue Technology"}
{0x00095e, "Masstech Group"}
{0x00095f, "Telebyte"}
{0x000960, "Yozan"}
{0x000961, "Switchgear and Instrumentation"}
{0x000962, "Sonitor Technologies AS"}
{0x000963, "Dominion Lasercom"}
{0x000964, "Hi-Techniques"}
{0x000965, "HyunJu Computer Co."}
{0x000966, "Thales Navigation"}
{0x000967, "Tachyon"}
{0x000968, "Technoventure"}
{0x000969, "Meret Optical Communications"}
{0x00096a, "Cloverleaf Communications"}
{0x00096b, "IBM"}
{0x00096c, "Imedia Semiconductor"}
{0x00096d, "Powernet Technologies"}
{0x00096e, "Giant Electronics"}
{0x00096f, "Beijing Zhongqing Elegant Tech.,Limited"}
{0x000970, "Vibration Research"}
{0x000971, "Time Management"}
{0x000972, "Securebase"}
{0x000973, "Lenten Technology Co."}
{0x000974, "Innopia Technologies"}
{0x000975, "fSONA Communications"}
{0x000976, "Datasoft Isdn Systems Gmbh"}
{0x000977, "Brunner Elektronik AG"}
{0x000978, "Aiji System Co."}
{0x000979, "Advanced Television Systems Committee"}
{0x00097a, "Louis Design Labs."}
{0x00097b, "Cisco Systems"}
{0x00097c, "Cisco Systems"}
{0x00097d, "SecWell Networks Oy"}
{0x00097e, "IMI Technology CO."}
{0x00097f, "Vsecure 2000"}
{0x000980, "Power Zenith"}
{0x000981, "Newport Networks"}
{0x000982, "Loewe Opta GmbH"}
{0x000983, "GlobalTop Technology"}
{0x000984, "MyCasa Network"}
{0x000985, "Auto Telecom Company"}
{0x000986, "Metalink"}
{0x000987, "Nishi Nippon Electric Wire & Cable Co."}
{0x000988, "Nudian Electron Co."}
{0x000989, "VividLogic"}
{0x00098a, "EqualLogic"}
{0x00098b, "Entropic Communications"}
{0x00098c, "Option Wireless Sweden"}
{0x00098d, "Velocity Semiconductor"}
{0x00098e, "ipcas GmbH"}
{0x00098f, "Cetacean Networks"}
{0x000990, "Acksys Communications & Systems"}
{0x000991, "GE Fanuc Automation Manufacturing"}
{0x000992, "InterEpoch Technology"}
{0x000993, "Visteon"}
{0x000994, "Cronyx Engineering"}
{0x000995, "Castle Technology"}
{0x000996, "RDI"}
{0x000997, "Nortel Networks"}
{0x000998, "Capinfo Company Limited"}
{0x000999, "CP Georges Renault"}
{0x00099a, "Elmo Company, Limited"}
{0x00099b, "Western Telematic"}
{0x00099c, "Naval Research Laboratory"}
{0x00099d, "Haliplex Communications"}
{0x00099e, "Testech"}
{0x00099f, "Videx"}
{0x0009a0, "Microtechno"}
{0x0009a1, "Telewise Communications"}
{0x0009a2, "Interface Co."}
{0x0009a3, "Leadfly Techologies"}
{0x0009a4, "Hartec"}
{0x0009a5, "Hansung Eletronic Industries Development CO."}
{0x0009a6, "Ignis Optics"}
{0x0009a7, "Bang & Olufsen A/S"}
{0x0009a8, "Eastmode Pte"}
{0x0009a9, "Ikanos Communications"}
{0x0009aa, "Data Comm for Business"}
{0x0009ab, "Netcontrol Oy"}
{0x0009ac, "Lanvoice"}
{0x0009ad, "Hyundai Syscomm"}
{0x0009ae, "Okano Electric Co."}
{0x0009af, "e-generis"}
{0x0009b0, "Onkyo"}
{0x0009b1, "Kanematsu Electronics"}
{0x0009b2, "L&F"}
{0x0009b3, "MCM Systems"}
{0x0009b4, "Kisan Telecom CO."}
{0x0009b5, "3J Tech. Co."}
{0x0009b6, "Cisco Systems"}
{0x0009b7, "Cisco Systems"}
{0x0009b8, "Entise Systems"}
{0x0009b9, "Action Imaging Solutions"}
{0x0009ba, "Maku Informationstechik Gmbh"}
{0x0009bb, "MathStar"}
{0x0009bc, "Digital Safety Technologies"}
{0x0009bd, "Epygi Technologies"}
{0x0009be, "Mamiya-OP Co."}
{0x0009bf, "Nintendo Co."}
{0x0009c0, "6wind"}
{0x0009c1, "Proces-data A/S"}
{0x0009c2, "Onity"}
{0x0009c3, "Netas"}
{0x0009c4, "Medicore Co."}
{0x0009c5, "Kingene Technology"}
{0x0009c6, "Visionics"}
{0x0009c7, "Movistec"}
{0x0009c8, "Sinagawa Tsushin Keisou Service"}
{0x0009c9, "BlueWINC Co."}
{0x0009ca, "iMaxNetworks(Shenzhen)Limited."}
{0x0009cb, "HBrain"}
{0x0009cc, "Moog GmbH"}
{0x0009cd, "Hudson Soft Co."}
{0x0009ce, "SpaceBridge Semiconductor"}
{0x0009cf, "iAd GmbH"}
{0x0009d0, "Solacom Technologies"}
{0x0009d1, "Seranoa Networks"}
{0x0009d2, "Mai Logic"}
{0x0009d3, "Western DataCom Co."}
{0x0009d4, "Transtech Networks"}
{0x0009d5, "Signal Communication"}
{0x0009d6, "KNC One GmbH"}
{0x0009d7, "DC Security Products"}
{0x0009d8, "Flt Communications AB"}
{0x0009d9, "Neoscale Systems"}
{0x0009da, "Control Module"}
{0x0009db, "eSpace"}
{0x0009dc, "Galaxis Technology AG"}
{0x0009dd, "Mavin Technology"}
{0x0009de, "Samjin Information & Communications Co."}
{0x0009df, "Vestel Komunikasyon Sanayi ve Ticaret A.S."}
{0x0009e0, "Xemics S.A."}
{0x0009e1, "Gemtek Technology Co."}
{0x0009e2, "Sinbon Electronics Co."}
{0x0009e3, "Angel Iglesias S.A."}
{0x0009e4, "K Tech Infosystem"}
{0x0009e5, "Hottinger Baldwin Messtechnik GmbH"}
{0x0009e6, "Cyber Switching"}
{0x0009e7, "ADC Techonology"}
{0x0009e8, "Cisco Systems"}
{0x0009e9, "Cisco Systems"}
{0x0009ea, "YEM"}
{0x0009eb, "HuMANDATA"}
{0x0009ec, "Daktronics"}
{0x0009ed, "CipherOptics"}
{0x0009ee, "Meikyo Electric Co."}
{0x0009ef, "Vocera Communications"}
{0x0009f0, "Shimizu Technology"}
{0x0009f1, "Yamaki Electric"}
{0x0009f2, "Cohu,, Electronics Division"}
{0x0009f3, "Well Communication"}
{0x0009f4, "Alcon Laboratories"}
{0x0009f5, "Emerson Network Power Co."}
{0x0009f6, "Shenzhen Eastern Digital Tech"}
{0x0009f7, "SED, a division of Calian"}
{0x0009f8, "Unimo Technology CO."}
{0x0009f9, "ART Japan CO."}
{0x0009fb, "Philips Patient Monitoring"}
{0x0009fc, "Ipflex"}
{0x0009fd, "Ubinetics Limited"}
{0x0009fe, "Daisy Technologies"}
{0x0009ff, "X.net 2000 GmbH"}
{0x000a00, "Mediatek"}
{0x000a01, "Sohoware"}
{0x000a02, "Annso CO."}
{0x000a03, "Endesa Servicios"}
{0x000a04, "3Com"}
{0x000a05, "Widax"}
{0x000a06, "Teledex"}
{0x000a07, "WebWayOne"}
{0x000a08, "Alpine Electronics"}
{0x000a09, "TaraCom Integrated Products"}
{0x000a0a, "Sunix Co."}
{0x000a0b, "Sealevel Systems"}
{0x000a0c, "Scientific Research"}
{0x000a0d, "FCI Deutschland GmbH"}
{0x000a0e, "Invivo Research"}
{0x000a0f, "Ilryung Telesys"}
{0x000a10, "Fast Media Integrations AG"}
{0x000a11, "ExPet Technologies"}
{0x000a12, "Azylex Technology"}
{0x000a13, "Honeywell Video Systems"}
{0x000a14, "Teco a.s."}
{0x000a15, "Silicon Data"}
{0x000a16, "Lassen Research"}
{0x000a17, "Nestar Communications"}
{0x000a18, "Vichel"}
{0x000a19, "Valere Power"}
{0x000a1a, "Imerge"}
{0x000a1b, "Stream Labs"}
{0x000a1c, "Bridge Information Co."}
{0x000a1d, "Optical Communications Products"}
{0x000a1e, "Red-M Products Limited"}
{0x000a1f, "ART Ware Telecommunication Co."}
{0x000a20, "SVA Networks"}
{0x000a21, "Integra Telecom Co."}
{0x000a22, "Amperion"}
{0x000a23, "Parama Networks"}
{0x000a24, "Octave Communications"}
{0x000a25, "Ceragon Networks"}
{0x000a26, "Ceia S.p.a."}
{0x000a27, "Apple Computer"}
{0x000a28, "Motorola"}
{0x000a29, "Pan Dacom Networking AG"}
{0x000a2a, "QSI Systems"}
{0x000a2b, "Etherstuff"}
{0x000a2c, "Active Tchnology"}
{0x000a2d, "Cabot Communications Limited"}
{0x000a2e, "Maple Networks CO."}
{0x000a2f, "Artnix"}
{0x000a30, "Johnson Controls-ASG"}
{0x000a31, "HCV Consulting"}
{0x000a32, "Xsido"}
{0x000a33, "Emulex"}
{0x000a34, "Identicard Systems Incorporated"}
{0x000a35, "Xilinx"}
{0x000a36, "Synelec Telecom Multimedia"}
{0x000a37, "Procera Networks"}
{0x000a38, "Apani Networks"}
{0x000a39, "LoPA Information Technology"}
{0x000a3a, "J-three International Holding Co."}
{0x000a3b, "GCT Semiconductor"}
{0x000a3c, "Enerpoint"}
{0x000a3d, "Elo Sistemas Eletronicos S.A."}
{0x000a3e, "Eads Telecom"}
{0x000a3f, "Data East"}
{0x000a40, "Crown Audio -- Harmanm International"}
{0x000a41, "Cisco Systems"}
{0x000a42, "Cisco Systems"}
{0x000a43, "Chunghwa Telecom Co."}
{0x000a44, "Avery Dennison Deutschland GmbH"}
{0x000a45, "Audio-Technica"}
{0x000a46, "ARO Welding Technologies SAS"}
{0x000a47, "Allied Vision Technologies"}
{0x000a48, "Albatron Technology"}
{0x000a49, "F5 Networks"}
{0x000a4a, "Targa Systems"}
{0x000a4b, "DataPower Technology"}
{0x000a4c, "Molecular Devices"}
{0x000a4d, "Noritz"}
{0x000a4e, "Unitek Electronics"}
{0x000a4f, "Brain Boxes Limited"}
{0x000a50, "Remotek"}
{0x000a51, "GyroSignal Technology Co."}
{0x000a52, "AsiaRF"}
{0x000a53, "Intronics, Incorporated"}
{0x000a54, "Laguna Hills"}
{0x000a55, "Markem"}
{0x000a56, "Hitachi Maxell"}
{0x000a57, "Hewlett-Packard Company - Standards"}
{0x000a58, "Ingenieur-Buero Freyer & Siegel"}
{0x000a59, "HW server"}
{0x000a5a, "GreenNET Technologies Co."}
{0x000a5b, "Power-One as"}
{0x000a5c, "Carel s.p.a."}
{0x000a5d, "PUC Founder (MSC) Berhad"}
{0x000a5e, "3COM"}
{0x000a5f, "almedio"}
{0x000a60, "Autostar Technology Pte"}
{0x000a61, "Cellinx Systems"}
{0x000a62, "Crinis Networks"}
{0x000a63, "DHD GmbH"}
{0x000a64, "Eracom Technologies"}
{0x000a65, "GentechMedia.co."}
{0x000a66, "Mitsubishi Electric System & Service Co."}
{0x000a67, "OngCorp"}
{0x000a68, "SolarFlare Communications"}
{0x000a69, "Sunny Bell Technology Co."}
{0x000a6a, "SVM Microwaves s.r.o."}
{0x000a6b, "Tadiran Telecom Business Systems"}
{0x000a6c, "Walchem"}
{0x000a6d, "EKS Elektronikservice GmbH"}
{0x000a6e, "Broadcast Technology Limited"}
{0x000a6f, "ZyFLEX Technologies"}
{0x000a70, "Mpls Forum"}
{0x000a71, "Avrio Technologies"}
{0x000a72, "STEC"}
{0x000a73, "Scientific Atlanta"}
{0x000a74, "Manticom Networks"}
{0x000a75, "Caterpillar"}
{0x000a76, "Beida Jade Bird Huaguang Technology Co."}
{0x000a77, "Bluewire Technologies"}
{0x000a78, "Olitec"}
{0x000a79, "Allied Telesis K.K. corega division"}
{0x000a7a, "Kyoritsu Electric Co."}
{0x000a7b, "Cornelius Consult"}
{0x000a7c, "Tecton"}
{0x000a7d, "Valo"}
{0x000a7e, "The Advantage Group"}
{0x000a7f, "Teradon Industries"}
{0x000a80, "Telkonet"}
{0x000a81, "Teima Audiotex S.L."}
{0x000a82, "Tatsuta System Electronics Co."}
{0x000a83, "Salto Systems S.L."}
{0x000a84, "Rainsun Enterprise Co."}
{0x000a85, "Plat'c2"}
{0x000a86, "Lenze"}
{0x000a87, "Integrated Micromachines"}
{0x000a88, "InCypher S.A."}
{0x000a89, "Creval Systems"}
{0x000a8a, "Cisco Systems"}
{0x000a8b, "Cisco Systems"}
{0x000a8c, "Guardware Systems"}
{0x000a8d, "Eurotherm Limited"}
{0x000a8e, "Invacom"}
{0x000a8f, "Aska International"}
{0x000a90, "Bayside Interactive"}
{0x000a91, "HemoCue AB"}
{0x000a92, "Presonus"}
{0x000a93, "W2 Networks"}
{0x000a94, "ShangHai cellink CO."}
{0x000a95, "Apple Computer"}
{0x000a96, "Mewtel Technology"}
{0x000a97, "Sonicblue"}
{0x000a98, "M+F Gwinner GmbH & Co"}
{0x000a99, "Calamp Wireless Networks"}
{0x000a9a, "Aiptek International"}
{0x000a9b, "TB Group"}
{0x000a9c, "Server Technology"}
{0x000a9d, "King Young Technology Co."}
{0x000a9e, "BroadWeb Corportation"}
{0x000a9f, "Pannaway Technologies"}
{0x000aa0, "Cedar Point Communications"}
{0x000aa1, "V V S Limited"}
{0x000aa2, "Systek"}
{0x000aa3, "Shimafuji Electric Co."}
{0x000aa4, "Shanghai Surveillance Technology Co"}
{0x000aa5, "Maxlink Industries Limited"}
{0x000aa6, "Hochiki"}
{0x000aa7, "FEI Electron Optics"}
{0x000aa8, "ePipe"}
{0x000aa9, "Brooks Automation GmbH"}
{0x000aaa, "AltiGen Communications"}
{0x000aab, "Toyota Technical Development"}
{0x000aac, "TerraTec Electronic GmbH"}
{0x000aad, "Stargames"}
{0x000aae, "Rosemount Process Analytical"}
{0x000aaf, "Pipal Systems"}
{0x000ab0, "Loytec Electronics Gmbh"}
{0x000ab1, "Genetec"}
{0x000ab2, "Fresnel Wireless Systems"}
{0x000ab3, "Fa. Gira"}
{0x000ab4, "Etic Telecommunications"}
{0x000ab5, "Digital Electronic Network"}
{0x000ab6, "Compunetix"}
{0x000ab7, "Cisco Systems"}
{0x000ab8, "Cisco Systems"}
{0x000ab9, "Astera Technologies"}
{0x000aba, "Arcon Technology Limited"}
{0x000abb, "Taiwan Secom Co"}
{0x000abc, "Seabridge"}
{0x000abd, "Rupprecht & Patashnick Co."}
{0x000abe, "Opnet Technologies CO."}
{0x000abf, "Hirota SS"}
{0x000ac0, "Fuyoh Video Industry CO."}
{0x000ac1, "Futuretel"}
{0x000ac2, "FiberHome Telecommunication Technologies CO."}
{0x000ac3, "eM Technics Co."}
{0x000ac4, "Daewoo Teletech Co."}
{0x000ac5, "Color Kinetics"}
{0x000ac6, "Overture Networks."}
{0x000ac7, "Unication Group"}
{0x000ac8, "Zpsys Co.,ltd. (planning&management)"}
{0x000ac9, "Zambeel"}
{0x000aca, "Yokoyama Shokai Co."}
{0x000acb, "Xpak MSA Group"}
{0x000acc, "Winnow Networks"}
{0x000acd, "Sunrich Technology Limited"}
{0x000ace, "Radiantech"}
{0x000acf, "Provideo Multimedia Co."}
{0x000ad0, "Niigata Develoment Center,  F.I.T. Co."}
{0x000ad1, "MWS"}
{0x000ad2, "Jepico"}
{0x000ad3, "Initech Co."}
{0x000ad4, "CoreBell Systems"}
{0x000ad5, "Brainchild Electronic Co."}
{0x000ad6, "BeamReach Networks"}
{0x000ad7, "Origin Electric Co."}
{0x000ad8, "IPCserv Technology"}
{0x000ad9, "Sony Ericsson Mobile Communications AB"}
{0x000ada, "Vindicator Technologies"}
{0x000adb, "SkyPilot Network"}
{0x000adc, "RuggedCom"}
{0x000add, "Allworx"}
{0x000ade, "Happy Communication Co."}
{0x000adf, "Gennum"}
{0x000ae0, "Fujitsu Softek"}
{0x000ae1, "EG Technology"}
{0x000ae2, "Binatone Electronics International"}
{0x000ae3, "Yang MEI Technology CO."}
{0x000ae4, "Wistron"}
{0x000ae5, "ScottCare"}
{0x000ae6, "Elitegroup Computer System Co. (ECS)"}
{0x000ae7, "Eliop S.A."}
{0x000ae8, "Cathay Roxus Information Technology Co."}
{0x000ae9, "AirVast Technology"}
{0x000aea, "Adam Elektroniksti."}
{0x000aeb, "Shenzhen Tp-Link Technology Co;"}
{0x000aec, "Koatsu Gas Kogyo Co."}
{0x000aed, "Harting Systems Gmbh & Co KG"}
{0x000aee, "GCD Hard- & Software GmbH"}
{0x000aef, "Otrum ASA"}
{0x000af0, "Shin-oh Electronics CO., R&D"}
{0x000af1, "Clarity Design"}
{0x000af2, "NeoAxiom"}
{0x000af3, "Cisco Systems"}
{0x000af4, "Cisco Systems"}
{0x000af5, "Airgo Networks"}
{0x000af6, "Emerson Climate Technologies Retail Solutions"}
{0x000af7, "Broadcom"}
{0x000af8, "American Telecare"}
{0x000af9, "HiConnect"}
{0x000afa, "Traverse Technologies Australia"}
{0x000afb, "Ambri Limited"}
{0x000afc, "Core Tec Communications"}
{0x000afd, "Viking Electronic Services"}
{0x000afe, "NovaPal"}
{0x000aff, "Kilchherr Elektronik AG"}
{0x000b00, "Fujian Start Computer Equipment Co."}
{0x000b01, "Daiichi Electronics CO."}
{0x000b02, "Dallmeier electronic"}
{0x000b03, "Taekwang Industrial Co."}
{0x000b04, "Volktek"}
{0x000b05, "Pacific Broadband Networks"}
{0x000b06, "Motorola Mobility"}
{0x000b07, "Voxpath Networks"}
{0x000b08, "Pillar Data Systems"}
{0x000b09, "Ifoundry Systems Singapore"}
{0x000b0a, "dBm Optics"}
{0x000b0b, "Corrent"}
{0x000b0c, "Agile Systems"}
{0x000b0d, "Air2U"}
{0x000b0e, "Trapeze Networks"}
{0x000b0f, "Nyquist Industrial Control BV"}
{0x000b10, "11wave Technonlogy Co."}
{0x000b11, "Himeji ABC Trading Co."}
{0x000b12, "Nuri Telecom Co."}
{0x000b13, "Zetron"}
{0x000b14, "ViewSonic"}
{0x000b15, "Platypus Technology"}
{0x000b16, "Communication Machinery"}
{0x000b17, "MKS Instruments"}
{0x000b18, "Private"}
{0x000b19, "Vernier Networks"}
{0x000b1a, "Industrial Defender"}
{0x000b1b, "Systronix"}
{0x000b1c, "Sibco bv"}
{0x000b1d, "LayerZero Power Systems"}
{0x000b1e, "Kappa Opto-electronics Gmbh"}
{0x000b1f, "I CON Computer Co."}
{0x000b20, "Hirata"}
{0x000b21, "G-Star Communications"}
{0x000b22, "Environmental Systems and Services"}
{0x000b23, "Siemens Subscriber Networks"}
{0x000b24, "AirLogic"}
{0x000b25, "Aeluros"}
{0x000b26, "Wetek"}
{0x000b27, "Scion"}
{0x000b28, "Quatech"}
{0x000b29, "LS(LG) Industrial Systems co."}
{0x000b2a, "Howtel Co."}
{0x000b2b, "Hostnet"}
{0x000b2c, "Eiki Industrial Co."}
{0x000b2d, "Danfoss"}
{0x000b2e, "Cal-Comp Electronics (Thailand) Public Company Limited Taipe"}
{0x000b2f, "bplan GmbH"}
{0x000b30, "Beijing Gongye Science & Technology Co."}
{0x000b31, "Yantai ZhiYang Scientific and technology industry CO."}
{0x000b32, "Vormetric"}
{0x000b33, "Vivato Technologies"}
{0x000b34, "ShangHai Broadband TechnologiesLTD"}
{0x000b35, "Quad Bit System co."}
{0x000b36, "Productivity Systems"}
{0x000b37, "Manufacture DES Montres Rolex SA"}
{0x000b38, "Knuerr GmbH"}
{0x000b39, "Keisoku Giken Co."}
{0x000b3a, "QuStream"}
{0x000b3b, "devolo AG"}
{0x000b3c, "Cygnal Integrated Products"}
{0x000b3d, "Contal OK"}
{0x000b3e, "BittWare"}
{0x000b3f, "Anthology Solutions"}
{0x000b40, "OpNext"}
{0x000b41, "Ing. Buero Dr. Beutlhauser"}
{0x000b42, "commax Co."}
{0x000b43, "Microscan Systems"}
{0x000b44, "Concord IDea"}
{0x000b45, "Cisco"}
{0x000b46, "Cisco"}
{0x000b47, "Advanced Energy"}
{0x000b48, "sofrel"}
{0x000b49, "RF-Link System"}
{0x000b4a, "Visimetrics (UK)"}
{0x000b4b, "Visiowave SA"}
{0x000b4c, "Clarion (M) Sdn Bhd"}
{0x000b4d, "Emuzed"}
{0x000b4e, "VertexRSI, General Dynamics SatCOM Technologies"}
{0x000b4f, "Verifone"}
{0x000b50, "Oxygnet"}
{0x000b51, "Micetek International"}
{0x000b52, "Joymax Electronics CO."}
{0x000b53, "Initium Co."}
{0x000b54, "BiTMICRO Networks"}
{0x000b55, "ADInstruments"}
{0x000b56, "Cybernetics"}
{0x000b57, "Silicon Laboratories"}
{0x000b58, "Astronautics C.A "}
{0x000b59, "ScriptPro"}
{0x000b5a, "HyperEdge"}
{0x000b5b, "Rincon Research"}
{0x000b5c, "Newtech Co."}
{0x000b5d, "Fujitsu Limited"}
{0x000b5e, "Audio Engineering Society"}
{0x000b5f, "Cisco Systems"}
{0x000b60, "Cisco Systems"}
{0x000b61, "Friedrich Ltze GmbH &Co."}
{0x000b62, "Ingenieurbuero fuer Elektronikdesign Ingo Mohnen"}
{0x000b63, "Kaleidescape"}
{0x000b64, "Kieback & Peter GmbH & Co KG"}
{0x000b65, "Sy.A.C. srl"}
{0x000b66, "Teralink Communications"}
{0x000b67, "Topview Technology"}
{0x000b68, "Addvalue Communications Pte"}
{0x000b69, "Franke Finland Oy"}
{0x000b6a, "Asiarock Incorporation"}
{0x000b6b, "Wistron Neweb"}
{0x000b6c, "Sychip"}
{0x000b6d, "Solectron Japan Nakaniida"}
{0x000b6e, "Neff Instrument"}
{0x000b6f, "Media Streaming Networks"}
{0x000b70, "Load Technology"}
{0x000b71, "Litchfield Communications"}
{0x000b72, "Lawo AG"}
{0x000b73, "Kodeos Communications"}
{0x000b74, "Kingwave Technology Co."}
{0x000b75, "Iosoft"}
{0x000b76, "ET&T Technology Co."}
{0x000b77, "Cogent Systems"}
{0x000b78, "Taifatech"}
{0x000b79, "X-COM"}
{0x000b7a, "Wave Science"}
{0x000b7b, "Test-Um"}
{0x000b7c, "Telex Communications"}
{0x000b7d, "Solomon Extreme International"}
{0x000b7e, "Saginomiya Seisakusho"}
{0x000b7f, "Align Engineering"}
{0x000b80, "Lycium Networks"}
{0x000b81, "Kaparel"}
{0x000b82, "Grandstream Networks"}
{0x000b83, "Datawatt B.V."}
{0x000b84, "Bodet"}
{0x000b85, "Cisco Systems"}
{0x000b86, "Aruba Networks"}
{0x000b87, "American Reliance"}
{0x000b88, "Vidisco"}
{0x000b89, "Top Global Technology"}
{0x000b8a, "Miteq"}
{0x000b8b, "Kerajet"}
{0x000b8c, "Flextronics"}
{0x000b8d, "Avvio Networks"}
{0x000b8e, "Ascent"}
{0x000b8f, "Akita Electronics Systems Co."}
{0x000b90, "Adva Optical Networking"}
{0x000b91, "Aglaia Gesellschaft fr Bildverarbeitung und Kommunikation"}
{0x000b92, "Ascom Danmark A/S"}
{0x000b93, "Ritter Elektronik"}
{0x000b94, "Digital Monitoring Products"}
{0x000b95, "eBet Gaming Systems"}
{0x000b96, "Innotrac Diagnostics Oy"}
{0x000b97, "Matsushita Electric Industrial Co."}
{0x000b98, "NiceTechVision"}
{0x000b99, "SensAble Technologies"}
{0x000b9a, "Shanghai Ulink Telecom Equipment Co."}
{0x000b9b, "Sirius System Co"}
{0x000b9c, "TriBeam Technologies"}
{0x000b9d, "TwinMOS Technologies"}
{0x000b9e, "Yasing Technology"}
{0x000b9f, "Neue Elsa Gmbh"}
{0x000ba0, "T&L Information"}
{0x000ba1, "Syscom"}
{0x000ba2, "Sumitomo Electric Networks"}
{0x000ba3, "Siemens AG"}
{0x000ba4, "Shiron Satellite Communications (1996)"}
{0x000ba5, "Quasar Cipta Mandiri"}
{0x000ba6, "Miyakawa Electric Works"}
{0x000ba7, "Maranti Networks"}
{0x000ba8, "Hanback Electronics CO."}
{0x000ba9, "CloudShield Technologies"}
{0x000baa, "Aiphone co."}
{0x000bab, "Advantech Technology (china) Co."}
{0x000bac, "3Com"}
{0x000bad, "PC-PoS"}
{0x000bae, "Vitals System"}
{0x000baf, "Wooju Communications Co"}
{0x000bb0, "Sysnet Telematica srl"}
{0x000bb1, "Super Star Technology Co."}
{0x000bb2, "Smallbig Technology"}
{0x000bb3, "RiT technologies"}
{0x000bb4, "RDC Semiconductor,"}
{0x000bb5, "nStor Technologies"}
{0x000bb6, "Metalligence Technology"}
{0x000bb7, "Micro Systems Co."}
{0x000bb8, "Kihoku Electronic Co."}
{0x000bb9, "Imsys AB"}
{0x000bba, "Harmonic Broadband Access Networks"}
{0x000bbb, "Etin Systems Co."}
{0x000bbc, "En Garde Systems"}
{0x000bbd, "Connexionz Limited"}
{0x000bbe, "Cisco Systems"}
{0x000bbf, "Cisco Systems"}
{0x000bc0, "China Iwncomm Co."}
{0x000bc1, "Bay Microsystems"}
{0x000bc2, "Corinex Communication"}
{0x000bc3, "Multiplex"}
{0x000bc4, "Biotronik Gmbh & Co"}
{0x000bc5, "SMC Networks"}
{0x000bc6, "ISAC"}
{0x000bc7, "Icet S.p.a."}
{0x000bc8, "AirFlow Networks"}
{0x000bc9, "Electroline Equipment"}
{0x000bca, "Datavan International"}
{0x000bcb, "Fagor Automation , S. Coop"}
{0x000bcc, "Jusan"}
{0x000bcd, "Hewlett-Packard Company"}
{0x000bce, "Free2move AB"}
{0x000bcf, "Agfa NDT"}
{0x000bd0, "XiMeta Technology Americas"}
{0x000bd1, "Aeronix"}
{0x000bd2, "Remopro Technology"}
{0x000bd3, "cd3o"}
{0x000bd4, "Beijing Wise Technology & Science DevelopmentLtd"}
{0x000bd5, "Nvergence"}
{0x000bd6, "Paxton Access"}
{0x000bd7, "Dorma Time + Access Gmbh"}
{0x000bd8, "Industrial Scientific"}
{0x000bd9, "General Hydrogen"}
{0x000bda, "EyeCross Co."}
{0x000bdb, "Dell ESG Pcba Test"}
{0x000bdc, "Akcp"}
{0x000bdd, "Tohoku Ricoh Co."}
{0x000bde, "Teldix Gmbh"}
{0x000bdf, "Shenzhen RouterD Networks Limited"}
{0x000be0, "SercoNet"}
{0x000be1, "Nokia NET Product Operations"}
{0x000be2, "Lumenera"}
{0x000be3, "Key Stream Co."}
{0x000be4, "Hosiden"}
{0x000be5, "Hims Korea Co."}
{0x000be6, "Datel Electronics"}
{0x000be7, "Comflux Technology"}
{0x000be8, "Aoip"}
{0x000be9, "Actel"}
{0x000bea, "Zultys Technologies"}
{0x000beb, "Systegra AG"}
{0x000bec, "Nippon Electric Instrument"}
{0x000bed, "ELM"}
{0x000bee, "inc.jet, Incorporated"}
{0x000bef, "Code"}
{0x000bf0, "MoTEX Products Co."}
{0x000bf1, "LAP Laser Applikations"}
{0x000bf2, "Chih-Kan Technology Co."}
{0x000bf3, "BAE Systems"}
{0x000bf4, "Private"}
{0x000bf5, "Shanghai Sibo Telecom Technology Co."}
{0x000bf6, "Nitgen Co."}
{0x000bf7, "Nidek Co."}
{0x000bf8, "Infinera"}
{0x000bf9, "Gemstone communications"}
{0x000bfa, "Exemys SRL"}
{0x000bfb, "D-NET International"}
{0x000bfc, "Cisco Systems"}
{0x000bfd, "Cisco Systems"}
{0x000bfe, "Castel Broadband Limited"}
{0x000bff, "Berkeley Camera Engineering"}
{0x000c00, "BEB Industrie-Elektronik AG"}
{0x000c01, "Abatron AG"}
{0x000c02, "ABB Oy"}
{0x000c03, "Hdmi Licensing"}
{0x000c04, "Tecnova"}
{0x000c05, "RPA Reserch Co."}
{0x000c06, "Nixvue Systems  Pte"}
{0x000c07, "Iftest AG"}
{0x000c08, "Humex Technologies"}
{0x000c09, "Hitachi IE Systems Co."}
{0x000c0a, "Guangdong Province Electronic Technology Research Institute"}
{0x000c0b, "Broadbus Technologies"}
{0x000c0c, "Appro Technology"}
{0x000c0d, "Communications & Power Industries / Satcom Division"}
{0x000c0e, "XtremeSpectrum"}
{0x000c0f, "Techno-One Co."}
{0x000c10, "PNI"}
{0x000c11, "Nippon Dempa Co."}
{0x000c12, "Micro-Optronic-Messtechnik GmbH"}
{0x000c13, "MediaQ"}
{0x000c14, "Diagnostic Instruments"}
{0x000c15, "CyberPower Systems"}
{0x000c16, "Concorde Microsystems"}
{0x000c17, "AJA Video Systems"}
{0x000c18, "Zenisu Keisoku"}
{0x000c19, "Telio Communications GmbH"}
{0x000c1a, "Quest Technical Solutions"}
{0x000c1b, "Oracom Co"}
{0x000c1c, "MicroWeb Co."}
{0x000c1d, "Mettler & Fuchs AG"}
{0x000c1e, "Global Cache"}
{0x000c1f, "Glimmerglass Networks"}
{0x000c20, "Fi WIn"}
{0x000c21, "Faculty of Science and Technology, Keio University"}
{0x000c22, "Double D Electronics"}
{0x000c23, "Beijing Lanchuan Tech. Co."}
{0x000c24, "Anator"}
{0x000c25, "Allied Telesis Labs"}
{0x000c26, "Weintek Labs."}
{0x000c27, "Sammy"}
{0x000c28, "Rifatron"}
{0x000c29, "VMware"}
{0x000c2a, "Octtel Communication Co."}
{0x000c2b, "Elias Technology"}
{0x000c2c, "Enwiser"}
{0x000c2d, "FullWave Technology Co."}
{0x000c2e, "Openet information technology(shenzhen) Co."}
{0x000c2f, "SeorimTechnology Co."}
{0x000c30, "Cisco"}
{0x000c31, "Cisco"}
{0x000c32, "Avionic Design Development GmbH"}
{0x000c33, "Compucase Enterprise Co."}
{0x000c34, "Vixen Co."}
{0x000c35, "KaVo Dental GmbH & Co. KG"}
{0x000c36, "Sharp Takaya Electronics Industry Co."}
{0x000c37, "Geomation"}
{0x000c38, "TelcoBridges"}
{0x000c39, "Sentinel Wireless"}
{0x000c3a, "Oxance"}
{0x000c3b, "Orion Electric Co."}
{0x000c3c, "MediaChorus"}
{0x000c3d, "Glsystech Co."}
{0x000c3e, "Crest Audio"}
{0x000c3f, "Cogent Defence & Security Networks,"}
{0x000c40, "Altech Controls"}
{0x000c41, "Cisco-Linksys"}
{0x000c42, "Routerboard.com"}
{0x000c43, "Ralink Technology"}
{0x000c44, "Automated Interfaces"}
{0x000c45, "Animation Technologies"}
{0x000c46, "Allied Telesyn"}
{0x000c47, "SK Teletech(R&D Planning Team)"}
{0x000c48, "QoStek"}
{0x000c49, "Dangaard Telecom RTC Division A/S"}
{0x000c4a, "Cygnus Microsystems (P) Limited"}
{0x000c4b, "Cheops Elektronik"}
{0x000c4c, "Arcor AG&Co."}
{0x000c4d, "Acra Control"}
{0x000c4e, "Winbest Technology CO"}
{0x000c4f, "UDTech Japan"}
{0x000c50, "Seagate Technology"}
{0x000c51, "Scientific Technologies"}
{0x000c52, "Roll Systems"}
{0x000c53, "Private"}
{0x000c54, "Pedestal Networks"}
{0x000c55, "Microlink Communications"}
{0x000c56, "Megatel Computer (1986)"}
{0x000c57, "Mackie Engineering Services Belgium Bvba"}
{0x000c58, "M&S Systems"}
{0x000c59, "Indyme Electronics"}
{0x000c5a, "IBSmm Industrieelektronik Multimedia"}
{0x000c5b, "Hanwang Technology Co."}
{0x000c5c, "GTN Systems B.V."}
{0x000c5d, "Chic Technology (china)"}
{0x000c5e, "Calypso Medical"}
{0x000c5f, "Avtec"}
{0x000c60, "ACM Systems"}
{0x000c61, "AC Tech DBA Advanced Digital"}
{0x000c62, "ABB AB, Cewe-Control "}
{0x000c63, "Zenith Electronics"}
{0x000c64, "X2 MSA Group"}
{0x000c65, "Sunin Telecom"}
{0x000c66, "Pronto Networks"}
{0x000c67, "OYO Electric Co."}
{0x000c68, "SigmaTel"}
{0x000c69, "National Radio Astronomy Observatory"}
{0x000c6a, "Mbari"}
{0x000c6b, "Kurz Industrie-Elektronik GmbH"}
{0x000c6c, "Elgato Systems"}
{0x000c6d, "Edwards"}
{0x000c6e, "Asustek Computer"}
{0x000c6f, "Amtek system co."}
{0x000c70, "ACC GmbH"}
{0x000c71, "Wybron"}
{0x000c72, "Tempearl Industrial Co."}
{0x000c73, "Telson Electronics CO."}
{0x000c74, "Rivertec"}
{0x000c75, "Oriental integrated electronics."}
{0x000c76, "Micro-star International CO."}
{0x000c77, "Life Racing"}
{0x000c78, "In-Tech Electronics Limited"}
{0x000c79, "Extel Communications P/L"}
{0x000c7a, "DaTARIUS Technologies GmbH"}
{0x000c7b, "Alpha Project Co."}
{0x000c7c, "Internet Information Image"}
{0x000c7d, "Teikoku Electric MFG. CO."}
{0x000c7e, "Tellium Incorporated"}
{0x000c7f, "synertronixx GmbH"}
{0x000c80, "Opelcomm"}
{0x000c81, "Schneider Electric (Australia) "}
{0x000c82, "Network Technologies"}
{0x000c83, "Logical Solutions"}
{0x000c84, "Eazix"}
{0x000c85, "Cisco Systems"}
{0x000c86, "Cisco Systems"}
{0x000c87, "AMD"}
{0x000c88, "Apache Micro Peripherals"}
{0x000c89, "AC Electric Vehicles"}
{0x000c8a, "Bose"}
{0x000c8b, "Connect Tech"}
{0x000c8c, "Kodicom Co."}
{0x000c8d, "Matrix Vision Gmbh"}
{0x000c8e, "Mentor Engineering"}
{0x000c8f, "Nergal s.r.l."}
{0x000c90, "Octasic"}
{0x000c91, "Riverhead Networks"}
{0x000c92, "WolfVision Gmbh"}
{0x000c93, "Xeline Co."}
{0x000c94, "United Electronic Industries, (EUI)"}
{0x000c95, "PrimeNet"}
{0x000c96, "OQO"}
{0x000c97, "NV ADB TTV Technologies SA"}
{0x000c98, "Letek Communications"}
{0x000c99, "Hitel Link Co."}
{0x000c9a, "Hitech Electronics"}
{0x000c9b, "EE Solutions"}
{0x000c9c, "Chongho information & communications"}
{0x000c9d, "AirWalk Communications"}
{0x000c9e, "MemoryLink"}
{0x000c9f, "NKE"}
{0x000ca0, "StorCase Technology"}
{0x000ca1, "Sigmacom Co."}
{0x000ca2, "Scopus Network Technologies"}
{0x000ca3, "Rancho Technology"}
{0x000ca4, "Prompttec Product Management GmbH"}
{0x000ca5, "Naman NZ"}
{0x000ca6, "Mintera"}
{0x000ca7, "Metro (Suzhou) Technologies Co."}
{0x000ca8, "Garuda Networks"}
{0x000ca9, "Ebtron"}
{0x000caa, "Cubic Transportation Systems"}
{0x000cab, "Commend International"}
{0x000cac, "Citizen Watch Co."}
{0x000cad, "BTU International"}
{0x000cae, "Ailocom Oy"}
{0x000caf, "TRI Term Co."}
{0x000cb0, "Star Semiconductor"}
{0x000cb1, "Salland Engineering (Europe) BV"}
{0x000cb2, "Comstar Co."}
{0x000cb3, "Round Co."}
{0x000cb4, "AutoCell Laboratories"}
{0x000cb5, "Premier Technolgies"}
{0x000cb6, "Nanjing SEU Mobile & Internet Technology Co."}
{0x000cb7, "Nanjing Huazhuo Electronics Co."}
{0x000cb8, "Medion AG"}
{0x000cb9, "LEA"}
{0x000cba, "Jamex"}
{0x000cbb, "Iskraemeco"}
{0x000cbc, "Iscutum"}
{0x000cbd, "Interface Masters"}
{0x000cbe, "Innominate Security Technologies AG"}
{0x000cbf, "Holy Stone Ent. Co."}
{0x000cc0, "Genera Oy"}
{0x000cc1, "Cooper Industries"}
{0x000cc2, "ControlNet (India) Private Limited"}
{0x000cc3, "BeWAN systems"}
{0x000cc4, "Tiptel AG"}
{0x000cc5, "Nextlink Co."}
{0x000cc6, "Ka-Ro electronics GmbH"}
{0x000cc7, "Intelligent Computer Solutions"}
{0x000cc8, "Xytronix Research & Design"}
{0x000cc9, "Ilwoo Data & Technology Co."}
{0x000cca, "Hitachi Global Storage Technologies"}
{0x000ccb, "Design Combus"}
{0x000ccc, "Aeroscout"}
{0x000ccd, "IEC - Tc57"}
{0x000cce, "Cisco Systems"}
{0x000ccf, "Cisco Systems"}
{0x000cd0, "Symetrix"}
{0x000cd1, "Sfom Technology"}
{0x000cd2, "Schaffner EMV AG"}
{0x000cd3, "Prettl Elektronik Radeberg GmbH"}
{0x000cd4, "Positron Public Safety Systems"}
{0x000cd5, "Passave"}
{0x000cd6, "Partner Tech"}
{0x000cd7, "Nallatech"}
{0x000cd8, "M. K. Juchheim GmbH & Co"}
{0x000cd9, "Itcare Co."}
{0x000cda, "FreeHand Systems"}
{0x000cdb, "Brocade Communications Systems"}
{0x000cdc, "Becs Technology"}
{0x000cdd, "AOS Technologies AG"}
{0x000cde, "ABB Stotz-kontakt Gmbh"}
{0x000cdf, "Pulnix America"}
{0x000ce0, "Trek Diagnostics"}
{0x000ce1, "The Open Group"}
{0x000ce2, "Rolls-Royce"}
{0x000ce3, "Option International N.V."}
{0x000ce4, "NeuroCom International"}
{0x000ce5, "Motorola Mobility"}
{0x000ce6, "Meru Networks"}
{0x000ce7, "MediaTek"}
{0x000ce8, "GuangZhou AnJuBao Co."}
{0x000ce9, "Bloomberg L.P."}
{0x000cea, "aphona Kommunikationssysteme"}
{0x000ceb, "Cnmp Networks"}
{0x000cec, "Spectracom"}
{0x000ced, "Real Digital Media"}
{0x000cee, "jp-embedded"}
{0x000cef, "Open Networks Engineering"}
{0x000cf0, "M & N GmbH"}
{0x000cf1, "Intel"}
{0x000cf2, "Gamesa Elica"}
{0x000cf3, "Call Image SA"}
{0x000cf4, "Akatsuki Electric Mfg.co."}
{0x000cf5, "InfoExpress"}
{0x000cf6, "Sitecom Europe BV"}
{0x000cf7, "Nortel Networks"}
{0x000cf8, "Nortel Networks"}
{0x000cf9, "ITT Flygt AB"}
{0x000cfa, "Digital Systems"}
{0x000cfb, "Korea Network Systems"}
{0x000cfc, "S2io Technologies"}
{0x000cfd, "Hyundai ImageQuest Co."}
{0x000cfe, "Grand Electronic Co."}
{0x000cff, "Mro-tek Limited"}
{0x000d00, "Seaway Networks"}
{0x000d01, "P&E Microcomputer Systems"}
{0x000d02, "NEC AccessTechnica"}
{0x000d03, "Matrics"}
{0x000d04, "Foxboro Eckardt Development GmbH"}
{0x000d05, "cybernet manufacturing"}
{0x000d06, "Compulogic Limited"}
{0x000d07, "Calrec Audio"}
{0x000d08, "AboveCable"}
{0x000d09, "Yuehua(Zhuhai) Electronic CO."}
{0x000d0a, "Projectiondesign as"}
{0x000d0b, "Buffalo"}
{0x000d0c, "MDI Security Systems"}
{0x000d0d, "ITSupported"}
{0x000d0e, "Inqnet Systems"}
{0x000d0f, "Finlux"}
{0x000d10, "Embedtronics Oy"}
{0x000d11, "Dentsply - Gendex"}
{0x000d12, "Axell"}
{0x000d13, "Wilhelm Rutenbeck GmbH&Co."}
{0x000d14, "Vtech Innovation LP dba Advanced American Telephones"}
{0x000d15, "Voipac s.r.o."}
{0x000d16, "UHS Systems"}
{0x000d17, "Turbo NetworksLtd"}
{0x000d18, "Mega-Trend Electronics CO."}
{0x000d19, "Robe Show Lighting"}
{0x000d1a, "Mustek System"}
{0x000d1b, "Kyoto Electronics Manufacturing Co."}
{0x000d1c, "Amesys Defense"}
{0x000d1d, "High-tek Harness ENT. CO."}
{0x000d1e, "Control Techniques"}
{0x000d1f, "AV Digital"}
{0x000d20, "Asahikasei Technosystem Co."}
{0x000d21, "Wiscore"}
{0x000d22, "Unitronics"}
{0x000d23, "Smart Solution"}
{0x000d24, "Sentec E&E CO."}
{0x000d25, "Sanden"}
{0x000d26, "Primagraphics Limited"}
{0x000d27, "Microplex Printware AG"}
{0x000d28, "Cisco"}
{0x000d29, "Cisco"}
{0x000d2a, "Scanmatic AS"}
{0x000d2b, "Racal Instruments"}
{0x000d2c, "Patapsco Designs"}
{0x000d2d, "NCT Deutschland GmbH"}
{0x000d2e, "Matsushita Avionics Systems"}
{0x000d2f, "AIN Comm.Tech.Co."}
{0x000d30, "IceFyre Semiconductor"}
{0x000d31, "Compellent Technologies"}
{0x000d32, "DispenseSource"}
{0x000d33, "Prediwave"}
{0x000d34, "Shell International Exploration and Production"}
{0x000d35, "PAC International"}
{0x000d36, "Wu Han Routon Electronic Co."}
{0x000d37, "Wiplug"}
{0x000d38, "Nissin"}
{0x000d39, "Network Electronics"}
{0x000d3a, "Microsoft"}
{0x000d3b, "Microelectronics Technology"}
{0x000d3c, "i.Tech Dynamic"}
{0x000d3d, "Hammerhead Systems"}
{0x000d3e, "Aplux Communications"}
{0x000d3f, "VTI Instruments"}
{0x000d40, "Verint Loronix Video Solutions"}
{0x000d41, "Siemens AG ICM MP UC RD IT KLF1"}
{0x000d42, "Newbest Development Limited"}
{0x000d43, "DRS Tactical Systems"}
{0x000d44, "Audio BU - Logitech"}
{0x000d45, "Tottori Sanyo Electric Co."}
{0x000d46, "Parker SSD Drives"}
{0x000d47, "Collex"}
{0x000d48, "Aewin Technologies Co."}
{0x000d49, "Triton Systems of Delaware"}
{0x000d4a, "Steag ETA-Optik"}
{0x000d4b, "Roku"}
{0x000d4c, "Outline Electronics"}
{0x000d4d, "Ninelanes"}
{0x000d4e, "NDR Co."}
{0x000d4f, "Kenwood"}
{0x000d50, "Galazar Networks"}
{0x000d51, "Divr Systems"}
{0x000d52, "Comart system"}
{0x000d53, "Beijing 5w Communication"}
{0x000d54, "3Com"}
{0x000d55, "Sanycom Technology Co."}
{0x000d56, "Dell Pcba Test"}
{0x000d57, "Fujitsu I-Network Systems Limited."}
{0x000d58, "Private"}
{0x000d59, "Amity Systems"}
{0x000d5a, "Tiesse SpA"}
{0x000d5b, "Smart Empire Investments Limited"}
{0x000d5c, "Robert Bosch GmbH, Vt-atmo"}
{0x000d5d, "Raritan Computer"}
{0x000d5e, "NEC Personal Products"}
{0x000d5f, "Minds"}
{0x000d60, "IBM"}
{0x000d61, "Giga-Byte Technology Co."}
{0x000d62, "Funkwerk Dabendorf GmbH"}
{0x000d63, "Dent Instruments"}
{0x000d64, "Comag Handels AG"}
{0x000d65, "Cisco Systems"}
{0x000d66, "Cisco Systems"}
{0x000d67, "BelAir Networks"}
{0x000d68, "Vinci Systems"}
{0x000d69, "TMT&D"}
{0x000d6a, "Redwood Technologies"}
{0x000d6b, "Mita-Teknik A/S"}
{0x000d6c, "M-Audio"}
{0x000d6d, "K-Tech Devices"}
{0x000d6e, "K-Patents Oy"}
{0x000d6f, "Ember"}
{0x000d70, "Datamax"}
{0x000d71, "boca systems"}
{0x000d72, "2Wire"}
{0x000d73, "Technical Support"}
{0x000d74, "Sand Network Systems"}
{0x000d75, "Kobian Pte - Taiwan Branch"}
{0x000d76, "Hokuto Denshi Co"}
{0x000d77, "FalconStor Software"}
{0x000d78, "Engineering & Security"}
{0x000d79, "Dynamic Solutions Co"}
{0x000d7a, "DiGATTO Asia Pacific Pte"}
{0x000d7b, "Consensys Computers"}
{0x000d7c, "Codian"}
{0x000d7d, "Afco Systems"}
{0x000d7e, "Axiowave Networks"}
{0x000d7f, "Midas  Communication Technologies PTE ( Foreign Branch)"}
{0x000d80, "Online Development"}
{0x000d81, "Pepperl+Fuchs GmbH"}
{0x000d82, "PHS srl"}
{0x000d83, "Sanmina-SCI Hungary "}
{0x000d84, "Makus"}
{0x000d85, "Tapwave"}
{0x000d86, "Huber + Suhner AG"}
{0x000d87, "Elitegroup Computer System Co. (ECS)"}
{0x000d88, "D-Link"}
{0x000d89, "Bils Technology"}
{0x000d8a, "Winners Electronics Co."}
{0x000d8b, "T&D"}
{0x000d8c, "Shanghai Wedone Digital CO."}
{0x000d8d, "ProLinx Communication Gateways"}
{0x000d8e, "Koden Electronics Co."}
{0x000d8f, "King Tsushin Kogyo Co."}
{0x000d90, "Factum Electronics AB"}
{0x000d91, "Eclipse (HQ Espana) S.L."}
{0x000d92, "Arima Communication"}
{0x000d93, "Apple Computer"}
{0x000d94, "Afar Communications"}
{0x000d95, "Opti-cell"}
{0x000d96, "Vtera Technology"}
{0x000d97, "Tropos Networks"}
{0x000d98, "S.W.A.C. Schmitt-Walter Automation Consult GmbH"}
{0x000d99, "Orbital Sciences; Launch Systems Group"}
{0x000d9a, "Infotec"}
{0x000d9b, "Heraeus Electro-Nite International N.V."}
{0x000d9c, "Elan GmbH & Co KG"}
{0x000d9d, "Hewlett-Packard Company"}
{0x000d9e, "Tokuden Ohizumi Seisakusyo Co."}
{0x000d9f, "RF Micro Devices"}
{0x000da0, "Nedap N.V."}
{0x000da1, "Mirae ITS Co."}
{0x000da2, "Infrant Technologies"}
{0x000da3, "Emerging Technologies Limited"}
{0x000da4, "Dosch & Amand Systems AG"}
{0x000da5, "Fabric7 Systems"}
{0x000da6, "Universal Switching"}
{0x000da7, "Private"}
{0x000da8, "Teletronics Technology"}
{0x000da9, "T.e.a.m. S.L."}
{0x000daa, "S.A.Tehnology co."}
{0x000dab, "Parker Hannifin GmbH Electromechanical Division Europe"}
{0x000dac, "Japan CBM"}
{0x000dad, "Dataprobe"}
{0x000dae, "Samsung Heavy Industries CO."}
{0x000daf, "Plexus (UK)"}
{0x000db0, "Olym-tech Co."}
{0x000db1, "Japan Network Service Co."}
{0x000db2, "Ammasso"}
{0x000db3, "SDO Communication Corperation"}
{0x000db4, "Netasq"}
{0x000db5, "Globalsat Technology"}
{0x000db6, "Broadcom"}
{0x000db7, "Sanko Electric Co"}
{0x000db8, "Schiller AG"}
{0x000db9, "PC Engines GmbH"}
{0x000dba, "Oc Document Technologies GmbH"}
{0x000dbb, "Nippon Dentsu Co."}
{0x000dbc, "Cisco Systems"}
{0x000dbd, "Cisco Systems"}
{0x000dbe, "Bel Fuse Europe"}
{0x000dbf, "TekTone Sound & Signal Mfg."}
{0x000dc0, "Spagat AS"}
{0x000dc1, "SafeWeb"}
{0x000dc2, "Private"}
{0x000dc3, "First Communication"}
{0x000dc4, "Emcore"}
{0x000dc5, "EchoStar Global B.V. "}
{0x000dc6, "DigiRose Technology Co."}
{0x000dc7, "Cosmic Engineering"}
{0x000dc8, "AirMagnet"}
{0x000dc9, "Thales Elektronik Systeme Gmbh"}
{0x000dca, "Tait Electronics"}
{0x000dcb, "Petcomkorea Co."}
{0x000dcc, "Neosmart"}
{0x000dcd, "Groupe Txcom"}
{0x000dce, "Dynavac Technology Pte"}
{0x000dcf, "Cidra"}
{0x000dd0, "TetraTec Instruments GmbH"}
{0x000dd1, "Stryker"}
{0x000dd2, "Simrad Optronics ASA"}
{0x000dd3, "Samwoo Telecommunication Co."}
{0x000dd4, "Symantec"}
{0x000dd5, "O'rite Technology Co."}
{0x000dd6, "ITI"}
{0x000dd7, "Bright"}
{0x000dd8, "BBN"}
{0x000dd9, "Anton Paar GmbH"}
{0x000dda, "Allied Telesis K.K."}
{0x000ddb, "Airwave Technologies"}
{0x000ddc, "VAC"}
{0x000ddd, "Proflo Telra Elektronk Sanay VE Tcaret A.."}
{0x000dde, "Joyteck Co."}
{0x000ddf, "Japan Image & Network"}
{0x000de0, "Icpdas Co."}
{0x000de1, "Control Products"}
{0x000de2, "CMZ Sistemi Elettronici"}
{0x000de3, "AT Sweden AB"}
{0x000de4, "Diginics"}
{0x000de5, "Samsung Thales"}
{0x000de6, "Youngbo Engineering Co."}
{0x000de7, "Snap-on OEM Group"}
{0x000de8, "Nasaco Electronics Pte."}
{0x000de9, "Napatech Aps"}
{0x000dea, "Kingtel Telecommunication"}
{0x000deb, "CompXs Limited"}
{0x000dec, "Cisco Systems"}
{0x000ded, "Cisco Systems"}
{0x000dee, "Andrew RF Power Amplifier Group"}
{0x000def, "Soc. Coop. Bilanciai"}
{0x000df0, "Qcom Technology"}
{0x000df1, "Ionix"}
{0x000df2, "Private"}
{0x000df3, "Asmax Solutions"}
{0x000df4, "Watertek Co."}
{0x000df5, "Teletronics International"}
{0x000df6, "Technology Thesaurus"}
{0x000df7, "Space Dynamics Lab"}
{0x000df8, "Orga Kartensysteme Gmbh"}
{0x000df9, "NDS Limited"}
{0x000dfa, "Micro Control Systems"}
{0x000dfb, "Komax AG"}
{0x000dfc, "Itfor"}
{0x000dfd, "Huges Hi-Tech,"}
{0x000dfe, "Hauppauge Computer Works"}
{0x000dff, "Chenming Mold Industry"}
{0x000e00, "Atrie"}
{0x000e01, "Asip Technologies"}
{0x000e02, "Advantech AMT"}
{0x000e03, "Emulex"}
{0x000e04, "CMA/Microdialysis AB"}
{0x000e05, "Wireless Matrix"}
{0x000e06, "Team Simoco"}
{0x000e07, "Sony Ericsson Mobile Communications AB"}
{0x000e08, "Cisco Linksys"}
{0x000e09, "Shenzhen Coship Software Co."}
{0x000e0a, "Sakuma Design Office"}
{0x000e0b, "Netac Technology Co."}
{0x000e0c, "Intel"}
{0x000e0d, "Hesch Schrder Gmbh"}
{0x000e0e, "ESA elettronica S.P.A."}
{0x000e0f, "Ermme"}
{0x000e10, "C-guys"}
{0x000e11, "BDT Bro- und Datentechnik GmbH & Co. KG"}
{0x000e12, "Adaptive Micro Systems"}
{0x000e13, "Accu-Sort Systems"}
{0x000e14, "Visionary Solutions"}
{0x000e15, "Tadlys"}
{0x000e16, "SouthWing S.L."}
{0x000e17, "Private"}
{0x000e18, "MyA Technology"}
{0x000e19, "LogicaCMG"}
{0x000e1a, "JPS Communications"}
{0x000e1b, "IAV GmbH"}
{0x000e1c, "Hach Company"}
{0x000e1d, "Arion Technology"}
{0x000e1e, "QLogic"}
{0x000e1f, "TCL Networks Equipment Co."}
{0x000e20, "Access Systems Americas"}
{0x000e21, "MTU Friedrichshafen GmbH"}
{0x000e22, "Private"}
{0x000e23, "Incipient"}
{0x000e24, "Huwell Technology"}
{0x000e25, "Hannae Technology Co."}
{0x000e26, "Gincom Technology"}
{0x000e27, "Crere Networks"}
{0x000e28, "Dynamic Ratings P/L"}
{0x000e29, "Shester Communications"}
{0x000e2a, "Private"}
{0x000e2b, "Safari Technologies"}
{0x000e2c, "Netcodec co."}
{0x000e2d, "Hyundai Digital Technology Co."}
{0x000e2e, "Edimax Technology Co."}
{0x000e2f, "Disetronic Medical Systems AG"}
{0x000e30, "Aeras Networks"}
{0x000e31, "Olympus Soft Imaging Solutions GmbH"}
{0x000e32, "Kontron Medical"}
{0x000e33, "Shuko Electronics Co."}
{0x000e34, "NexGen City"}
{0x000e35, "Intel"}
{0x000e36, "Heinesys"}
{0x000e37, "Harms & Wende GmbH &KG"}
{0x000e38, "Cisco Systems"}
{0x000e39, "Cisco Systems"}
{0x000e3a, "Cirrus Logic"}
{0x000e3b, "Hawking Technologies"}
{0x000e3c, "Transact Technologies"}
{0x000e3d, "Televic N.V."}
{0x000e3e, "Sun Optronics"}
{0x000e3f, "Soronti"}
{0x000e40, "Nortel Networks"}
{0x000e41, "Nihon Mechatronics Co."}
{0x000e42, "Motic Incoporation"}
{0x000e43, "G-Tek Electronics Sdn. Bhd."}
{0x000e44, "Digital"}
{0x000e45, "Beijing Newtry Electronic Technology"}
{0x000e46, "Niigata Seimitsu Co."}
{0x000e47, "NCI System Co."}
{0x000e48, "Lipman TransAction Solutions"}
{0x000e49, "Forsway Scandinavia AB"}
{0x000e4a, "Changchun Huayu Webpad Co."}
{0x000e4b, "atrium c and"}
{0x000e4c, "Bermai"}
{0x000e4d, "Numesa"}
{0x000e4e, "Waveplus Technology Co."}
{0x000e4f, "Trajet GmbH"}
{0x000e50, "Thomson Telecom Belgium"}
{0x000e51, "tecna elettronica srl"}
{0x000e52, "Optium"}
{0x000e53, "AV Tech"}
{0x000e54, "AlphaCell Wireless"}
{0x000e55, "Auvitran"}
{0x000e56, "4G Systems GmbH & Co. KG"}
{0x000e57, "Iworld Networking"}
{0x000e58, "Sonos"}
{0x000e59, "Sagem SA"}
{0x000e5a, "Telefield"}
{0x000e5b, "ParkerVision - Direct2Data"}
{0x000e5c, "Motorola Mobility"}
{0x000e5d, "Triple Play Technologies A/S"}
{0x000e5e, "Raisecom Technology"}
{0x000e5f, "activ-net GmbH & Co. KG"}
{0x000e60, "360SUN Digital Broadband"}
{0x000e61, "Microtrol Limited"}
{0x000e62, "Nortel Networks"}
{0x000e63, "Lemke Diagnostics GmbH"}
{0x000e64, "Elphel"}
{0x000e65, "TransCore"}
{0x000e66, "Hitachi Advanced Digital"}
{0x000e67, "Eltis Microelectronics"}
{0x000e68, "E-TOP Network Technology"}
{0x000e69, "China Electric Power Research Institute"}
{0x000e6a, "3Com"}
{0x000e6b, "Janitza electronics GmbH"}
{0x000e6c, "Device Drivers Limited"}
{0x000e6d, "Murata Manufacturing Co."}
{0x000e6e, "Micrelec  Electronics S.A"}
{0x000e6f, "Iris Berhad"}
{0x000e70, "in2 Networks"}
{0x000e71, "Gemstar Technology Development"}
{0x000e72, "CTS electronics"}
{0x000e73, "Tpack A/S"}
{0x000e74, "Solar Telecom. Tech"}
{0x000e75, "New York Air Brake"}
{0x000e76, "Gemsoc Innovision"}
{0x000e77, "Decru"}
{0x000e78, "Amtelco"}
{0x000e79, "Ample Communications"}
{0x000e7a, "GemWon Communications Co."}
{0x000e7b, "Toshiba"}
{0x000e7c, "Televes S.A."}
{0x000e7d, "Electronics Line 3000"}
{0x000e7e, "ionSign Oy"}
{0x000e7f, "Hewlett-Packard Company"}
{0x000e80, "Thomson Technology"}
{0x000e81, "Devicescape Software"}
{0x000e82, "Commtech Wireless"}
{0x000e83, "Cisco Systems"}
{0x000e84, "Cisco Systems"}
{0x000e85, "Catalyst Enterprises"}
{0x000e86, "Alcatel North America"}
{0x000e87, "adp Gauselmann GmbH"}
{0x000e88, "Videotron"}
{0x000e89, "Clematic"}
{0x000e8a, "Avara Technologies"}
{0x000e8b, "Astarte Technology Co"}
{0x000e8c, "Siemens AG A&D ET"}
{0x000e8d, "Systems in Progress Holding GmbH"}
{0x000e8e, "SparkLAN Communications"}
{0x000e8f, "Sercomm"}
{0x000e90, "Ponico"}
{0x000e91, "Navico Auckland"}
{0x000e92, "Millinet Co."}
{0x000e93, "Milnio 3 Sistemas Electrnicos"}
{0x000e94, "Maas International BV"}
{0x000e95, "Fujiya Denki Seisakusho Co."}
{0x000e96, "Cubic Defense Applications"}
{0x000e97, "Ultracker Technology CO."}
{0x000e98, "HME Clear-Com"}
{0x000e99, "Spectrum Digital"}
{0x000e9a, "BOE Technology Group Co."}
{0x000e9b, "Ambit Microsystems"}
{0x000e9c, "Pemstar"}
{0x000e9d, "Tiscali UK"}
{0x000e9e, "Topfield Co."}
{0x000e9f, "Temic SDS Gmbh"}
{0x000ea0, "NetKlass Technology"}
{0x000ea1, "Formosa Teletek"}
{0x000ea2, "McAfee"}
{0x000ea3, "Cncr-it Co.,ltd,hangzhou P.r.china"}
{0x000ea4, "Certance"}
{0x000ea5, "Blip Systems"}
{0x000ea6, "Asustek Computer"}
{0x000ea7, "Endace Technology"}
{0x000ea8, "United Technologists Europe Limited"}
{0x000ea9, "Shanghai Xun Shi Communications Equipment Co."}
{0x000eaa, "Scalent Systems"}
{0x000eab, "Cray"}
{0x000eac, "Mintron Enterprise CO."}
{0x000ead, "Metanoia Technologies"}
{0x000eae, "Gawell Technologies"}
{0x000eaf, "Castel"}
{0x000eb0, "Solutions Radio BV"}
{0x000eb1, "Newcotech"}
{0x000eb2, "Micro-Research Finland Oy"}
{0x000eb3, "Hewlett-Packard"}
{0x000eb4, "Guangzhou Gaoke Communications Technologyltd."}
{0x000eb5, "Ecastle Electronics Co."}
{0x000eb6, "Riverbed Technology"}
{0x000eb7, "Knovative"}
{0x000eb8, "Iiga co."}
{0x000eb9, "Hashimoto Electronics Industry Co."}
{0x000eba, "Hanmi Semiconductor CO."}
{0x000ebb, "Everbee Networks"}
{0x000ebc, "Paragon Fidelity GmbH"}
{0x000ebd, "Burdick, a Quinton Compny"}
{0x000ebe, "B&B Electronics Manufacturing Co."}
{0x000ebf, "Remsdaq Limited"}
{0x000ec0, "Nortel Networks"}
{0x000ec1, "Mynah Technologies"}
{0x000ec2, "Lowrance Electronics"}
{0x000ec3, "Logic Controls"}
{0x000ec4, "Iskra Transmission d.d."}
{0x000ec5, "Digital Multitools"}
{0x000ec6, "Asix Electronics"}
{0x000ec7, "Motorola Korea"}
{0x000ec8, "Zoran"}
{0x000ec9, "Yoko Technology"}
{0x000eca, "Wtss"}
{0x000ecb, "VineSys Technology"}
{0x000ecc, "Tableau"}
{0x000ecd, "Skov A/S"}
{0x000ece, "S.I.T.T.I. S.p.A."}
{0x000ecf, "Profibus Nutzerorganisation e.V."}
{0x000ed0, "Privaris"}
{0x000ed1, "Osaka Micro Computer."}
{0x000ed2, "Filtronic plc"}
{0x000ed3, "Epicenter"}
{0x000ed4, "Cresitt Industrie"}
{0x000ed5, "Copan Systems"}
{0x000ed6, "Cisco Systems"}
{0x000ed7, "Cisco Systems"}
{0x000ed8, "Aktino"}
{0x000ed9, "Aksys"}
{0x000eda, "C-tech United"}
{0x000edb, "XiNCOM"}
{0x000edc, "Tellion"}
{0x000edd, "Shure Incorporated"}
{0x000ede, "Remec"}
{0x000edf, "PLX Technology"}
{0x000ee0, "Mcharge"}
{0x000ee1, "ExtremeSpeed"}
{0x000ee2, "Custom Engineering S.p.A."}
{0x000ee3, "Chiyu Technology Co."}
{0x000ee4, "BOE Technology Group Co."}
{0x000ee5, "bitWallet"}
{0x000ee6, "Adimos Systems"}
{0x000ee7, "AAC Electronics"}
{0x000ee8, "zioncom"}
{0x000ee9, "WayTech Development"}
{0x000eea, "Shadong Luneng Jicheng Electronics,Co."}
{0x000eeb, "Sandmartin(zhong shan)Electronics Co."}
{0x000eec, "Orban"}
{0x000eed, "Nokia Danmark A/S"}
{0x000eee, "Muco Industrie BV"}
{0x000eef, "Private"}
{0x000ef0, "Festo AG & Co. KG"}
{0x000ef1, "Ezquest"}
{0x000ef2, "Infinico"}
{0x000ef3, "Smarthome"}
{0x000ef4, "Kasda Digital Technology Co."}
{0x000ef5, "iPAC Technology Co."}
{0x000ef6, "E-TEN Information Systems Co."}
{0x000ef7, "Vulcan Portals"}
{0x000ef8, "SBC ASI"}
{0x000ef9, "REA Elektronik GmbH"}
{0x000efa, "Optoway Technology Incorporation"}
{0x000efb, "Macey Enterprises"}
{0x000efc, "Jtag Technologies B.V."}
{0x000efd, "Fujinon"}
{0x000efe, "EndRun Technologies"}
{0x000eff, "Megasolution"}
{0x000f00, "Legra Systems"}
{0x000f01, "Digitalks"}
{0x000f02, "Digicube Technology Co."}
{0x000f03, "Com&c CO."}
{0x000f04, "cim-usa"}
{0x000f05, "3B System"}
{0x000f06, "Nortel Networks"}
{0x000f07, "Mangrove Systems"}
{0x000f08, "Indagon Oy"}
{0x000f09, "Private"}
{0x000f0a, "Clear Edge Networks"}
{0x000f0b, "Kentima Technologies AB"}
{0x000f0c, "Synchronic Engineering"}
{0x000f0d, "Hunt Electronic Co."}
{0x000f0e, "WaveSplitter Technologies"}
{0x000f0f, "Real ID Technology Co."}
{0x000f10, "RDM"}
{0x000f11, "Prodrive B.V."}
{0x000f12, "Panasonic Europe"}
{0x000f13, "Nisca"}
{0x000f14, "Mindray Co."}
{0x000f15, "Kjaerulff1 A/S"}
{0x000f16, "JAY HOW Technology CO.,"}
{0x000f17, "Insta Elektro GmbH"}
{0x000f18, "Industrial Control Systems"}
{0x000f19, "Boston Scientific"}
{0x000f1a, "Gaming Support B.V."}
{0x000f1b, "Ego Systems"}
{0x000f1c, "DigitAll World Co."}
{0x000f1d, "Cosmo Techs Co."}
{0x000f1e, "Chengdu KT Electricof High & New Technology"}
{0x000f1f, "WW Pcba Test"}
{0x000f20, "Hewlett-Packard Company"}
{0x000f21, "Scientific Atlanta"}
{0x000f22, "Helius"}
{0x000f23, "Cisco Systems"}
{0x000f24, "Cisco Systems"}
{0x000f25, "AimValley B.V."}
{0x000f26, "WorldAccxx "}
{0x000f27, "Teal Electronics"}
{0x000f28, "Itronix"}
{0x000f29, "Augmentix"}
{0x000f2a, "Cableware Electronics"}
{0x000f2b, "Greenbell Systems"}
{0x000f2c, "Uplogix"}
{0x000f2d, "Chung-hsin Electric & Machinery Mfg.corp."}
{0x000f2e, "Megapower International"}
{0x000f2f, "W-linx Technology CO."}
{0x000f30, "Raza Microelectronics"}
{0x000f31, "Allied Vision Technologies Canada"}
{0x000f32, "LuTong Electronic Technology Co."}
{0x000f33, "Duali"}
{0x000f34, "Cisco Systems"}
{0x000f35, "Cisco Systems"}
{0x000f36, "Accurate Techhnologies"}
{0x000f37, "Xambala Incorporated"}
{0x000f38, "Netstar"}
{0x000f39, "Iris Sensors"}
{0x000f3a, "Hisharp"}
{0x000f3b, "Fuji System Machines Co."}
{0x000f3c, "Endeleo Limited"}
{0x000f3d, "D-Link"}
{0x000f3e, "CardioNet"}
{0x000f3f, "Big Bear Networks"}
{0x000f40, "Optical Internetworking Forum"}
{0x000f41, "Zipher"}
{0x000f42, "Xalyo Systems"}
{0x000f43, "Wasabi Systems"}
{0x000f44, "Tivella"}
{0x000f45, "Stretch"}
{0x000f46, "Sinar AG"}
{0x000f47, "Robox SPA"}
{0x000f48, "Polypix"}
{0x000f49, "Northover Solutions Limited"}
{0x000f4a, "Kyushu-kyohan co."}
{0x000f4b, "Oracle"}
{0x000f4c, "Elextech"}
{0x000f4d, "TalkSwitch"}
{0x000f4e, "Cellink"}
{0x000f4f, "Cadmus Technology"}
{0x000f50, "StreamScale Limited"}
{0x000f51, "Azul Systems"}
{0x000f52, "York Refrigeration, Marine & Controls"}
{0x000f53, "Solarflare Communications"}
{0x000f54, "Entrelogic"}
{0x000f55, "Datawire Communication Networks"}
{0x000f56, "Continuum Photonics"}
{0x000f57, "Cablelogic Co."}
{0x000f58, "Adder Technology Limited"}
{0x000f59, "Phonak Communications AG"}
{0x000f5a, "Peribit Networks"}
{0x000f5b, "Delta Information Systems"}
{0x000f5c, "Day One Digital Media Limited"}
{0x000f5d, "PacketFront International AB"}
{0x000f5e, "Veo"}
{0x000f5f, "Nicety Technologies (NTS)"}
{0x000f60, "Lifetron Co."}
{0x000f61, "Hewlett-Packard Company"}
{0x000f62, "Alcatel Bell Space N.V."}
{0x000f63, "Obzerv Technologies"}
{0x000f64, "D&R Electronica Weesp BV"}
{0x000f65, "icube"}
{0x000f66, "Cisco-Linksys"}
{0x000f67, "West Instruments"}
{0x000f68, "Vavic Network Technology"}
{0x000f69, "SEW Eurodrive GmbH & Co. KG"}
{0x000f6a, "Nortel Networks"}
{0x000f6b, "GateWare Communications GmbH"}
{0x000f6c, "Addi-data Gmbh"}
{0x000f6d, "Midas Engineering"}
{0x000f6e, "BBox"}
{0x000f6f, "FTA Communication Technologies"}
{0x000f70, "Wintec Industries"}
{0x000f71, "Sanmei Electronics Co."}
{0x000f72, "Sandburst"}
{0x000f73, "RS Automation Co."}
{0x000f74, "Qamcom Technology AB"}
{0x000f75, "First Silicon Solutions"}
{0x000f76, "Digital Keystone"}
{0x000f77, "Dentum Co."}
{0x000f78, "Datacap Systems"}
{0x000f79, "Bluetooth Interest Group"}
{0x000f7a, "BeiJing NuQX Technology CO."}
{0x000f7b, "Arce Sistemas"}
{0x000f7c, "ACTi"}
{0x000f7d, "Xirrus"}
{0x000f7e, "Ablerex Electronics Co."}
{0x000f7f, "Ubstorage Co."}
{0x000f80, "Trinity Security Systems"}
{0x000f81, "Secure Info Imaging"}
{0x000f82, "Mortara Instrument"}
{0x000f83, "Brainium Technologies"}
{0x000f84, "Astute Networks"}
{0x000f85, "Addo-japan"}
{0x000f86, "Research In Motion Limited"}
{0x000f87, "Maxcess International"}
{0x000f88, "Ametek"}
{0x000f89, "Winnertec System Co."}
{0x000f8a, "WideView"}
{0x000f8b, "Orion MultiSystems"}
{0x000f8c, "Gigawavetech Pte"}
{0x000f8d, "Fast Tv-server AG"}
{0x000f8e, "Dongyang Telecom Co."}
{0x000f8f, "Cisco Systems"}
{0x000f90, "Cisco Systems"}
{0x000f91, "Aerotelecom Co."}
{0x000f92, "Microhard Systems"}
{0x000f93, "Landis+Gyr"}
{0x000f94, "Genexis"}
{0x000f95, "Elecom Co.,ltd Laneed Division"}
{0x000f96, "Telco Systems"}
{0x000f97, "Avanex"}
{0x000f98, "Avamax Co."}
{0x000f99, "Apac Opto Electronics"}
{0x000f9a, "Synchrony"}
{0x000f9b, "Ross Video Limited"}
{0x000f9c, "Panduit"}
{0x000f9d, "DisplayLink (UK)"}
{0x000f9e, "Murrelektronik GmbH"}
{0x000f9f, "Motorola Mobility"}
{0x000fa0, "Canon Korea Business Solutions"}
{0x000fa1, "Gigabit Systems"}
{0x000fa2, "Digital Path Networks"}
{0x000fa3, "Alpha Networks"}
{0x000fa4, "Sprecher Automation GmbH"}
{0x000fa5, "BWA Technology GmbH"}
{0x000fa6, "S2 Security"}
{0x000fa7, "Raptor Networks Technology"}
{0x000fa8, "Photometrics"}
{0x000fa9, "PC Fabrik"}
{0x000faa, "Nexus Technologies"}
{0x000fab, "Kyushu Electronics Systems"}
{0x000fac, "Ieee 802.11"}
{0x000fad, "FMN communications GmbH"}
{0x000fae, "E2O Communications"}
{0x000faf, "Dialog"}
{0x000fb0, "Compal Electronics"}
{0x000fb1, "Cognio"}
{0x000fb2, "Broadband Pacenet (India) Pvt."}
{0x000fb3, "Actiontec Electronics"}
{0x000fb4, "Timespace Technology"}
{0x000fb5, "Netgear"}
{0x000fb6, "Europlex Technologies"}
{0x000fb7, "Cavium Networks"}
{0x000fb8, "CallURL"}
{0x000fb9, "Adaptive Instruments"}
{0x000fba, "Tevebox AB"}
{0x000fbb, "Nokia Siemens Networks GmbH & Co. KG"}
{0x000fbc, "Onkey Technologies"}
{0x000fbd, "MRV Communications (Networks)"}
{0x000fbe, "e-w/you"}
{0x000fbf, "DGT Sp. z o.o."}
{0x000fc0, "Delcomp"}
{0x000fc1, "Wave"}
{0x000fc2, "Uniwell"}
{0x000fc3, "PalmPalm Technology"}
{0x000fc4, "NST co."}
{0x000fc5, "KeyMed"}
{0x000fc6, "Eurocom Industries A/S"}
{0x000fc7, "Dionica R&D"}
{0x000fc8, "Chantry Networks"}
{0x000fc9, "Allnet GmbH"}
{0x000fca, "A-jin Techline CO"}
{0x000fcb, "3Com"}
{0x000fcc, "Netopia"}
{0x000fcd, "Nortel Networks"}
{0x000fce, "Kikusui Electronics"}
{0x000fcf, "Datawind Research"}
{0x000fd0, "Astri"}
{0x000fd1, "Applied Wireless Identifications Group"}
{0x000fd2, "EWA Technologies"}
{0x000fd3, "Digium"}
{0x000fd4, "Soundcraft"}
{0x000fd5, "Schwechat - Rise"}
{0x000fd6, "Sarotech Co."}
{0x000fd7, "Harman Music Group"}
{0x000fd8, "Force"}
{0x000fd9, "FlexDSL Telecommunications AG"}
{0x000fda, "Yazaki"}
{0x000fdb, "Westell Technologies"}
{0x000fdc, "Ueda Japan  Radio Co."}
{0x000fdd, "Sordin AB"}
{0x000fde, "Sony Ericsson Mobile Communications AB"}
{0x000fdf, "Solomon Technology"}
{0x000fe0, "NComputing Co."}
{0x000fe1, "ID Digital"}
{0x000fe2, "Hangzhou H3C Technologies Co."}
{0x000fe3, "Damm Cellular Systems A/S"}
{0x000fe4, "Pantech Co."}
{0x000fe5, "Mercury Security"}
{0x000fe6, "MBTech Systems"}
{0x000fe7, "Lutron Electronics Co."}
{0x000fe8, "Lobos"}
{0x000fe9, "GW Technologies Co."}
{0x000fea, "Giga-Byte Technology Co."}
{0x000feb, "Cylon Controls"}
{0x000fec, "Arkus"}
{0x000fed, "Anam Electronics Co."}
{0x000fee, "XTec, Incorporated"}
{0x000fef, "Thales e-Transactions GmbH"}
{0x000ff0, "Sunray Co."}
{0x000ff1, "nex-G Systems Pte.Ltd"}
{0x000ff2, "Loud Technologies"}
{0x000ff3, "Jung Myoung Communications&Technology"}
{0x000ff4, "Guntermann & Drunck GmbH"}
{0x000ff5, "GN&S company"}
{0x000ff6, "Darfon Electronics"}
{0x000ff7, "Cisco Systems"}
{0x000ff8, "Cisco  Systems"}
{0x000ff9, "Valcretec"}
{0x000ffa, "Optinel Systems"}
{0x000ffb, "Nippon Denso Industry Co."}
{0x000ffc, "Merit Li-Lin Ent."}
{0x000ffd, "Glorytek Network"}
{0x000ffe, "G-pro Computer"}
{0x000fff, "Control4"}
{0x001000, "Cable Television Laboratories"}
{0x001001, "Citel"}
{0x001002, "Actia"}
{0x001003, "Imatron"}
{0x001004, "THE Brantley Coile Company"}
{0x001005, "UEC Commercial"}
{0x001006, "Thales Contact Solutions"}
{0x001007, "Cisco Systems"}
{0x001008, "Vienna Systems"}
{0x001009, "Horo Quartz"}
{0x00100a, "Williams Communications Group"}
{0x00100b, "Cisco Systems"}
{0x00100c, "ITO CO."}
{0x00100d, "Cisco Systems"}
{0x00100e, "Micro Linear Coporation"}
{0x00100f, "Industrial CPU Systems"}
{0x001010, "Initio"}
{0x001011, "Cisco Systems"}
{0x001012, "Processor Systems (I) PVT"}
{0x001013, "Kontron America"}
{0x001014, "Cisco Systems"}
{0x001015, "OOmon"}
{0x001016, "T.sqware"}
{0x001017, "Bosch Access Systems GmbH"}
{0x001018, "Broadcom"}
{0x001019, "Sirona Dental Systems Gmbh & Co. KG"}
{0x00101a, "PictureTel"}
{0x00101b, "Cornet Technology"}
{0x00101c, "OHM Technologies INTL"}
{0x00101d, "Winbond Electronics"}
{0x00101e, "Matsushita Electronic Instruments"}
{0x00101f, "Cisco Systems"}
{0x001020, "Hand Held Products"}
{0x001021, "Encanto Networks"}
{0x001022, "SatCom Media"}
{0x001023, "Network Equipment Technologies"}
{0x001024, "Nagoya Electric Works CO."}
{0x001025, "Grayhill"}
{0x001026, "Accelerated Networks"}
{0x001027, "L-3 Communications East"}
{0x001028, "Computer Technica"}
{0x001029, "Cisco Systems"}
{0x00102a, "ZF Microsystems"}
{0x00102b, "Umax Data Systems"}
{0x00102c, "Lasat Networks A/S"}
{0x00102d, "Hitachi Software Engineering"}
{0x00102e, "Network Systems & Technologies PVT."}
{0x00102f, "Cisco Systems"}
{0x001030, "Eion"}
{0x001031, "Objective Communications"}
{0x001032, "Alta Technology"}
{0x001033, "Accesslan Communications"}
{0x001034, "GNP Computers"}
{0x001035, "Elitegroup Computer Systems CO."}
{0x001036, "Inter-tel Integrated Systems"}
{0x001037, "CYQ've Technology Co."}
{0x001038, "Micro Research Institute"}
{0x001039, "Vectron Systems AG"}
{0x00103a, "Diamond Network Tech"}
{0x00103b, "Hippi Networking Forum"}
{0x00103c, "IC Ensemble"}
{0x00103d, "Phasecom"}
{0x00103e, "Netschools"}
{0x00103f, "Tollgrade Communications"}
{0x001040, "Intermec"}
{0x001041, "Bristol Babcock"}
{0x001042, "Alacritech"}
{0x001043, "A2"}
{0x001044, "InnoLabs"}
{0x001045, "Nortel Networks"}
{0x001046, "Alcorn Mcbride"}
{0x001047, "Echo Eletric CO."}
{0x001048, "Htrc Automation"}
{0x001049, "ShoreTel"}
{0x00104a, "The Parvus"}
{0x00104b, "3com"}
{0x00104c, "LeCroy"}
{0x00104d, "Surtec Industries"}
{0x00104e, "Ceologic"}
{0x00104f, "Oracle"}
{0x001050, "Rion CO."}
{0x001051, "Cmicro"}
{0x001052, "Mettler-toledo (albstadt) Gmbh"}
{0x001053, "Computer Technology"}
{0x001054, "Cisco Systems"}
{0x001055, "Fujitsu Microelectronics"}
{0x001056, "Sodick CO."}
{0x001057, "Rebel.com"}
{0x001058, "ArrowPoint Communications"}
{0x001059, "Diablo Research CO."}
{0x00105a, "3com"}
{0x00105b, "NET Insight AB"}
{0x00105c, "Quantum Designs (h.k.)"}
{0x00105d, "Draeger Medical"}
{0x00105e, "Hekimian Laboratories"}
{0x00105f, "Zodiac Data Systems"}
{0x001060, "Billionton Systems"}
{0x001061, "Hostlink"}
{0x001062, "NX Server"}
{0x001063, "Starguide Digital Networks"}
{0x001064, "DNPG"}
{0x001065, "Radyne"}
{0x001066, "Advanced Control Systems"}
{0x001067, "Ericsson"}
{0x001068, "Comos Telecom"}
{0x001069, "Helioss Communications"}
{0x00106a, "Digital Microwave"}
{0x00106b, "Sonus Networks"}
{0x00106c, "Infratec AG"}
{0x00106d, "Axxcelera Broadband Wireless"}
{0x00106e, "Tadiran COM."}
{0x00106f, "Trenton Technology"}
{0x001070, "Caradon Trend"}
{0x001071, "Advanet"}
{0x001072, "GVN Technologies"}
{0x001073, "Technobox"}
{0x001074, "Aten International CO."}
{0x001075, "Maxtor"}
{0x001076, "Eurem Gmbh"}
{0x001077, "SAF Drive Systems"}
{0x001078, "Nuera Communications"}
{0x001079, "Cisco Systems"}
{0x00107a, "AmbiCom"}
{0x00107b, "Cisco Systems"}
{0x00107c, "P-com"}
{0x00107d, "Aurora Communications"}
{0x00107e, "Bachmann Electronic Gmbh"}
{0x00107f, "Crestron Electronics"}
{0x001080, "Metawave Communications"}
{0x001081, "DPS"}
{0x001082, "JNA Telecommunications Limited"}
{0x001083, "Hewlett-packard Company"}
{0x001084, "K-bot Communications"}
{0x001085, "Polaris Communications"}
{0x001086, "Atto Technology"}
{0x001087, "Xstreamis PLC"}
{0x001088, "American Networks"}
{0x001089, "WebSonic"}
{0x00108a, "TeraLogic"}
{0x00108b, "Laseranimation Sollinger Gmbh"}
{0x00108c, "Fujitsu Telecommunications Europe"}
{0x00108d, "Johnson Controls"}
{0x00108e, "Hugh Symons Concept Technologies"}
{0x00108f, "Raptor Systems"}
{0x001090, "Cimetrics"}
{0x001091, "NO Wires Needed BV"}
{0x001092, "Netcore"}
{0x001093, "CMS Computers"}
{0x001094, "Performance Analysis Broadband, Spirent plc"}
{0x001095, "Thomson"}
{0x001096, "Tracewell Systems"}
{0x001097, "WinNet Metropolitan Communications Systems"}
{0x001098, "Starnet Technologies"}
{0x001099, "InnoMedia"}
{0x00109a, "Netline"}
{0x00109b, "Emulex"}
{0x00109c, "M-system CO."}
{0x00109d, "Clarinet Systems"}
{0x00109e, "Aware"}
{0x00109f, "PAVO"}
{0x0010a0, "Innovex Technologies"}
{0x0010a1, "Kendin Semiconductor"}
{0x0010a2, "TNS"}
{0x0010a3, "Omnitronix"}
{0x0010a4, "Xircom"}
{0x0010a5, "Oxford Instruments"}
{0x0010a6, "Cisco Systems"}
{0x0010a7, "Unex Technology"}
{0x0010a8, "Reliance Computer"}
{0x0010a9, "Adhoc Technologies"}
{0x0010aa, "Media4"}
{0x0010ab, "Koito Electric Industries"}
{0x0010ac, "Imci Technologies"}
{0x0010ad, "Softronics USB"}
{0x0010ae, "Shinko Electric Industries CO."}
{0x0010af, "TAC Systems"}
{0x0010b0, "Meridian Technology"}
{0x0010b1, "For-a CO."}
{0x0010b2, "Coactive Aesthetics"}
{0x0010b3, "Nokia Multimedia Terminals"}
{0x0010b4, "Atmosphere Networks"}
{0x0010b5, "Accton Technology"}
{0x0010b6, "Entrata Communications"}
{0x0010b7, "Coyote Technologies"}
{0x0010b8, "Ishigaki Computer System CO."}
{0x0010b9, "Maxtor"}
{0x0010ba, "Martinho-davis Systems"}
{0x0010bb, "Data & Information Technology"}
{0x0010bc, "Aastra Telecom"}
{0x0010bd, "THE Telecommunication Technology Committee (ttc)"}
{0x0010be, "March Networks"}
{0x0010bf, "InterAir Wireless"}
{0x0010c0, "ARMA"}
{0x0010c1, "OI Electric CO."}
{0x0010c2, "Willnet"}
{0x0010c3, "Csi-control Systems"}
{0x0010c4, "Media Links CO."}
{0x0010c5, "Protocol Technologies"}
{0x0010c6, "Universal Global Scientific Industrial Co."}
{0x0010c7, "Data Transmission Network"}
{0x0010c8, "Communications Electronics Security Group"}
{0x0010c9, "Mitsubishi Electronics Logistic Support CO."}
{0x0010ca, "Telco Systems"}
{0x0010cb, "Facit K.K."}
{0x0010cc, "CLP Computer Logistik Planung Gmbh"}
{0x0010cd, "Interface Concept"}
{0x0010ce, "Volamp"}
{0x0010cf, "Fiberlane Communications"}
{0x0010d0, "Witcom"}
{0x0010d1, "Top Layer Networks"}
{0x0010d2, "Nitto Tsushinki CO."}
{0x0010d3, "Grips Electronic Gmbh"}
{0x0010d4, "Storage Computer"}
{0x0010d5, "Imasde Canarias"}
{0x0010d6, "ITT - A/cd"}
{0x0010d7, "Argosy Research"}
{0x0010d8, "Calista"}
{0x0010d9, "IBM Japan, Fujisawa Mt+d"}
{0x0010da, "Motion Engineering"}
{0x0010db, "Juniper Networks"}
{0x0010dc, "Micro-star International CO."}
{0x0010dd, "Enable Semiconductor"}
{0x0010de, "International Datacasting"}
{0x0010df, "Rise Computer"}
{0x0010e0, "Oracle"}
{0x0010e1, "S.I. TECH"}
{0x0010e2, "ArrayComm"}
{0x0010e3, "Hewlett-Packard Company"}
{0x0010e4, "NSI"}
{0x0010e5, "Solectron Texas"}
{0x0010e6, "Applied Intelligent Systems"}
{0x0010e7, "BreezeCom"}
{0x0010e8, "Telocity, Incorporated"}
{0x0010e9, "Raidtec"}
{0x0010ea, "Adept Technology"}
{0x0010eb, "Selsius Systems"}
{0x0010ec, "RPCG"}
{0x0010ed, "Sundance Technology"}
{0x0010ee, "CTI Products"}
{0x0010ef, "Dbtel Incorporated"}
{0x0010f1, "I-O"}
{0x0010f2, "Antec"}
{0x0010f3, "Nexcom International Co."}
{0x0010f4, "Vertical Communications"}
{0x0010f5, "Amherst Systems"}
{0x0010f6, "Cisco Systems"}
{0x0010f7, "Iriichi Technologies"}
{0x0010f8, "Niikke Techno System Co."}
{0x0010f9, "Unique Systems"}
{0x0010fa, "Apple"}
{0x0010fb, "Zida Technologies Limited"}
{0x0010fc, "Broadband Networks"}
{0x0010fd, "Cocom A/S"}
{0x0010fe, "Digital Equipment"}
{0x0010ff, "Cisco Systems"}
{0x001100, "Schneider Electric"}
{0x001101, "CET Technologies Pte"}
{0x001102, "Aurora Multimedia"}
{0x001103, "kawamura electric"}
{0x001104, "Telexy"}
{0x001105, "Sunplus Technology Co."}
{0x001106, "Siemens NV (Belgium)"}
{0x001107, "RGB Networks"}
{0x001108, "Orbital Data"}
{0x001109, "Micro-Star International"}
{0x00110a, "Hewlett-Packard Company"}
{0x00110b, "Franklin Technology Systems"}
{0x00110c, "Atmark Techno"}
{0x00110d, "Sanblaze Technology"}
{0x00110e, "Tsurusaki Sealand Transportation Co."}
{0x00110f, "netplat"}
{0x001110, "Maxanna Technology Co."}
{0x001111, "Intel"}
{0x001112, "Honeywell Cmss"}
{0x001113, "Fraunhofer Fokus"}
{0x001114, "EverFocus Electronics"}
{0x001115, "Epin Technologies"}
{0x001116, "Coteau Vert CO."}
{0x001117, "Cesnet"}
{0x001118, "BLX IC Design"}
{0x001119, "Solteras"}
{0x00111a, "Motorola Mobility"}
{0x00111b, "Targa Systems Div L-3 Communications Canada"}
{0x00111c, "Pleora Technologies"}
{0x00111d, "Hectrix Limited"}
{0x00111e, "Epsg (ethernet Powerlink Standardization Group)"}
{0x00111f, "Doremi Labs"}
{0x001120, "Cisco Systems"}
{0x001121, "Cisco Systems"}
{0x001122, "Cimsys"}
{0x001123, "Appointech"}
{0x001124, "Apple Computer"}
{0x001125, "IBM"}
{0x001126, "Venstar"}
{0x001127, "TASI"}
{0x001128, "Streamit"}
{0x001129, "Paradise Datacom"}
{0x00112a, "Niko NV"}
{0x00112b, "NetModule AG"}
{0x00112c, "IZT GmbH"}
{0x00112d, "iPulse Systems"}
{0x00112e, "Ceicom"}
{0x00112f, "Asustek Computer"}
{0x001130, "Allied Telesis (Hong Kong)"}
{0x001131, "Unatech. Co."}
{0x001132, "Synology Incorporated"}
{0x001133, "Siemens Austria Simea"}
{0x001134, "MediaCell"}
{0x001135, "Grandeye"}
{0x001136, "Goodrich Sensor Systems"}
{0x001137, "Aichi Electric CO."}
{0x001138, "Taishin CO."}
{0x001139, "Stoeber Antriebstechnik Gmbh + Co. KG."}
{0x00113a, "Shinboram"}
{0x00113b, "Micronet Communications"}
{0x00113c, "Micronas GmbH"}
{0x00113d, "KN Soltec Co."}
{0x00113e, "JL"}
{0x00113f, "Alcatel DI"}
{0x001140, "Nanometrics"}
{0x001141, "GoodMan"}
{0x001142, "E-smartcom "}
{0x001143, "Dell"}
{0x001144, "Assurance Technology"}
{0x001145, "ValuePoint Networks"}
{0x001146, "Telecard-Pribor"}
{0x001147, "Secom-IndustryLTD."}
{0x001148, "Prolon Control Systems"}
{0x001149, "Proliphix"}
{0x00114a, "Kayaba Industry Co"}
{0x00114b, "Francotyp-Postalia GmbH"}
{0x00114c, "caffeina applied research"}
{0x00114d, "Atsumi Electric Co."}
{0x00114e, "690885 Ontario"}
{0x00114f, "US Digital Television"}
{0x001150, "Belkin"}
{0x001151, "Mykotronx"}
{0x001152, "Eidsvoll Electronics AS"}
{0x001153, "Trident Tek"}
{0x001154, "Webpro Technologies"}
{0x001155, "Sevis Systems"}
{0x001156, "Pharos Systems NZ"}
{0x001157, "OF Networks Co."}
{0x001158, "Nortel Networks"}
{0x001159, "Matisse Networks"}
{0x00115a, "Ivoclar Vivadent AG"}
{0x00115b, "Elitegroup Computer System Co. (ECS)"}
{0x00115c, "Cisco"}
{0x00115d, "Cisco"}
{0x00115e, "ProMinent Dosiertechnik GmbH"}
{0x00115f, "ITX Security Co."}
{0x001160, "Artdio Company Co."}
{0x001161, "NetStreams"}
{0x001162, "Star Micronics Co."}
{0x001163, "System SPA DEPT. Electronics"}
{0x001164, "Acard Technology"}
{0x001165, "Znyx Networks"}
{0x001166, "Taelim Electronics Co."}
{0x001167, "Integrated System Solution"}
{0x001168, "HomeLogic"}
{0x001169, "EMS Satcom"}
{0x00116a, "Domo"}
{0x00116b, "Digital Data Communications Asia Co."}
{0x00116c, "Nanwang Multimedia"}
{0x00116d, "American Time and Signal"}
{0x00116e, "PePLink"}
{0x00116f, "Netforyou Co."}
{0x001170, "GSC SRL"}
{0x001171, "Dexter Communications"}
{0x001172, "Cotron"}
{0x001173, "Smart Modular Technologies"}
{0x001174, "Wibhu Technologies"}
{0x001175, "PathScale"}
{0x001176, "Intellambda Systems"}
{0x001177, "Coaxial Networks"}
{0x001178, "Chiron Technology"}
{0x001179, "Singular Technology Co."}
{0x00117a, "Singim International"}
{0x00117b, "Bchi Labortechnik AG"}
{0x00117c, "e-zy.net"}
{0x00117d, "ZMD America"}
{0x00117e, "Progeny"}
{0x00117f, "Neotune Information Technology"}
{0x001180, "Motorola Mobility"}
{0x001181, "InterEnergyLtd,"}
{0x001182, "IMI Norgren"}
{0x001183, "Datalogic Mobile"}
{0x001184, "Humo Laboratory"}
{0x001185, "Hewlett-Packard Company"}
{0x001186, "Prime Systems"}
{0x001187, "Category Solutions"}
{0x001188, "Enterasys"}
{0x001189, "Aerotech"}
{0x00118a, "Viewtran Technology Limited"}
{0x00118b, "Alcatel-Lucent, Enterprise Business Group"}
{0x00118c, "Missouri Department of Transportation"}
{0x00118d, "Hanchang System"}
{0x00118e, "Halytech Mace"}
{0x00118f, "Eutech Instruments PTE."}
{0x001190, "Digital Design"}
{0x001191, "CTS-Clima Temperatur Systeme GmbH"}
{0x001192, "Cisco Systems"}
{0x001193, "Cisco Systems"}
{0x001194, "Chi Mei Communication Systems"}
{0x001195, "D-Link"}
{0x001196, "Actuality Systems"}
{0x001197, "Monitoring Technologies Limited"}
{0x001198, "Prism Media Products Limited"}
{0x001199, "2wcom GmbH"}
{0x00119a, "Alkeria srl"}
{0x00119b, "Telesynergy Research"}
{0x00119c, "EP&T Energy"}
{0x00119d, "Diginfo Technology"}
{0x00119e, "Solectron Brazil"}
{0x00119f, "Nokia Danmark A/S"}
{0x0011a0, "Vtech Engineering Canada"}
{0x0011a1, "Vision Netware Co."}
{0x0011a2, "Manufacturing Technology"}
{0x0011a3, "LanReady Technologies"}
{0x0011a4, "JStream Technologies"}
{0x0011a5, "Fortuna Electronic"}
{0x0011a6, "Sypixx Networks"}
{0x0011a7, "Infilco Degremont"}
{0x0011a8, "Quest Technologies"}
{0x0011a9, "Moimstone Co."}
{0x0011aa, "Uniclass Technology, Co."}
{0x0011ab, "Trustable Technology Co."}
{0x0011ac, "Simtec Electronics"}
{0x0011ad, "Shanghai Ruijie Technology"}
{0x0011ae, "Motorola Mobility"}
{0x0011af, "Medialink-i"}
{0x0011b0, "Fortelink"}
{0x0011b1, "BlueExpert Technology"}
{0x0011b2, "2001 Technology"}
{0x0011b3, "Yoshimiya Co."}
{0x0011b4, "Westermo Teleindustri AB"}
{0x0011b5, "Shenzhen Powercom Co."}
{0x0011b6, "Open Systems International"}
{0x0011b7, "Octalix B.V."}
{0x0011b8, "Liebherr - Elektronik GmbH"}
{0x0011b9, "Inner Range"}
{0x0011ba, "Elexol"}
{0x0011bb, "Cisco Systems"}
{0x0011bc, "Cisco Systems"}
{0x0011bd, "Bombardier Transportation"}
{0x0011be, "AGP Telecom Co."}
{0x0011bf, "Aesys S.p.a."}
{0x0011c0, "Aday Technology"}
{0x0011c1, "4P Mobile Data Processing"}
{0x0011c2, "United Fiber Optic Communication"}
{0x0011c3, "Transceiving System Technology"}
{0x0011c4, "Terminales de Telecomunicacion Terrestre"}
{0x0011c5, "TEN Technology"}
{0x0011c6, "Seagate Technology"}
{0x0011c7, "Raymarine UK"}
{0x0011c8, "Powercom Co."}
{0x0011c9, "MTT"}
{0x0011ca, "Long Range Systems"}
{0x0011cb, "Jacobsons AB"}
{0x0011cc, "Guangzhou Jinpeng Group Co."}
{0x0011cd, "Axsun Technologies"}
{0x0011ce, "Ubisense Limited"}
{0x0011cf, "Thrane & Thrane A/S"}
{0x0011d0, "Tandberg Data ASA"}
{0x0011d1, "Soft Imaging System GmbH"}
{0x0011d2, "Perception Digital"}
{0x0011d3, "NextGenTel Holding ASA"}
{0x0011d4, "NetEnrich"}
{0x0011d5, "Hangzhou Sunyard System Engineering Co."}
{0x0011d6, "HandEra"}
{0x0011d7, "eWerks"}
{0x0011d8, "Asustek Computer"}
{0x0011d9, "TiVo"}
{0x0011da, "Vivaas Technology"}
{0x0011db, "Land-Cellular"}
{0x0011dc, "Glunz & Jensen"}
{0x0011dd, "Fromus TEC. Co."}
{0x0011de, "Eurilogic"}
{0x0011df, "Current Energy"}
{0x0011e0, "U-media Communications"}
{0x0011e1, "Arcelik A.S"}
{0x0011e2, "Hua Jung Components Co."}
{0x0011e3, "Thomson"}
{0x0011e4, "Danelec Electronics A/S"}
{0x0011e5, "KCodes"}
{0x0011e6, "Scientific Atlanta"}
{0x0011e7, "Worldsat - Texas de France"}
{0x0011e8, "Tixi.Com"}
{0x0011e9, "Starnex CO."}
{0x0011ea, "Iwics"}
{0x0011eb, "Innovative Integration"}
{0x0011ec, "Avix"}
{0x0011ed, "802 Global"}
{0x0011ee, "Estari"}
{0x0011ef, "Conitec Datensysteme GmbH"}
{0x0011f0, "Wideful Limited"}
{0x0011f1, "QinetiQ"}
{0x0011f2, "Institute of Network Technologies"}
{0x0011f3, "NeoMedia Europe AG"}
{0x0011f4, "woori-net"}
{0x0011f5, "Askey Computer"}
{0x0011f6, "Asia Pacific Microsystems "}
{0x0011f7, "Shenzhen Forward Industry Co."}
{0x0011f8, "Airaya"}
{0x0011f9, "Nortel Networks"}
{0x0011fa, "Rane"}
{0x0011fb, "Heidelberg Engineering GmbH"}
{0x0011fc, "Harting Electric Gmbh &KG"}
{0x0011fd, "Korg"}
{0x0011fe, "Keiyo System Research"}
{0x0011ff, "Digitro Tecnologia Ltda"}
{0x001200, "Cisco"}
{0x001201, "Cisco"}
{0x001202, "Decrane Aerospace - Audio International"}
{0x001203, "Activ Networks"}
{0x001204, "u10 Networks"}
{0x001205, "Terrasat Communications"}
{0x001206, "iQuest (NZ)"}
{0x001207, "Head Strong International Limited"}
{0x001208, "Gantner Instruments GmbH"}
{0x001209, "Fastrax"}
{0x00120a, "Emerson Electric GmbH & Co. OHG"}
{0x00120b, "Chinasys Technologies Limited"}
{0x00120c, "CE-Infosys Pte"}
{0x00120d, "Advanced Telecommunication Technologies"}
{0x00120e, "AboCom"}
{0x00120f, "Ieee 802.3"}
{0x001210, "WideRay"}
{0x001211, "Protechna Herbst GmbH & Co. KG"}
{0x001212, "Plus "}
{0x001213, "Metrohm AG"}
{0x001214, "Koenig & Bauer AG"}
{0x001215, "iStor Networks"}
{0x001216, "ICP Internet Communication Payment AG"}
{0x001217, "Cisco-Linksys"}
{0x001218, "Aruze"}
{0x001219, "Ahead Communication Systems"}
{0x00121a, "Techno Soft Systemnics"}
{0x00121b, "Sound Devices"}
{0x00121c, "Parrot S.A."}
{0x00121d, "Netfabric"}
{0x00121e, "Juniper Networks"}
{0x00121f, "Harding Intruments"}
{0x001220, "Cadco Systems"}
{0x001221, "B.Braun Melsungen AG"}
{0x001222, "Skardin (UK)"}
{0x001223, "Pixim"}
{0x001224, "NexQL"}
{0x001225, "Motorola Mobility"}
{0x001226, "Japan Direx"}
{0x001227, "Franklin Electric Co."}
{0x001228, "Data"}
{0x001229, "BroadEasy Technologies Co."}
{0x00122a, "VTech Telecommunications"}
{0x00122b, "Virbiage"}
{0x00122c, "Soenen Controls N.V."}
{0x00122d, "SiNett"}
{0x00122e, "Signal Technology - Aisd"}
{0x00122f, "Sanei Electric"}
{0x001230, "Picaso Infocommunication CO."}
{0x001231, "Motion Control Systems"}
{0x001232, "LeWiz Communications"}
{0x001233, "JRC Tokki Co."}
{0x001234, "Camille Bauer"}
{0x001235, "Andrew"}
{0x001236, "ConSentry Networks"}
{0x001237, "Texas Instruments"}
{0x001238, "SetaBox Technology Co."}
{0x001239, "S Net Systems"}
{0x00123a, "Posystech"}
{0x00123b, "KeRo Systems ApS"}
{0x00123c, "Second Rule"}
{0x00123d, "GES"}
{0x00123e, "Erune Technology Co."}
{0x00123f, "Dell"}
{0x001240, "Amoi Electronics Co."}
{0x001241, "a2i marketing center"}
{0x001242, "Millennial Net"}
{0x001243, "Cisco"}
{0x001244, "Cisco"}
{0x001245, "Zellweger Analytics"}
{0x001246, "T.O.M Technology."}
{0x001247, "Samsung Electronics Co."}
{0x001248, "EMC (Kashya)"}
{0x001249, "Delta Elettronica S.p.A."}
{0x00124a, "Dedicated Devices"}
{0x00124b, "Texas Instruments"}
{0x00124c, "Bbwm"}
{0x00124d, "Inducon BV"}
{0x00124e, "XAC Automation"}
{0x00124f, "Tyco Thermal Controls"}
{0x001250, "Tokyo Aircaft Instrument Co."}
{0x001251, "Silink"}
{0x001252, "Citronix"}
{0x001253, "AudioDev AB"}
{0x001254, "Spectra Technologies Holdings Company"}
{0x001255, "NetEffect Incorporated"}
{0x001256, "LG Information & COMM."}
{0x001257, "LeapComm Communication Technologies"}
{0x001258, "Activis Polska"}
{0x001259, "Thermo Electron Karlsruhe"}
{0x00125a, "Microsoft"}
{0x00125b, "Kaimei Electroni"}
{0x00125c, "Green Hills Software"}
{0x00125d, "CyberNet"}
{0x00125e, "Caen"}
{0x00125f, "Awind"}
{0x001260, "Stanton Magnetics"}
{0x001261, "Adaptix"}
{0x001262, "Nokia Danmark A/S"}
{0x001263, "Data Voice Technologies GmbH"}
{0x001264, "daum electronic gmbh"}
{0x001265, "Enerdyne Technologies"}
{0x001266, "Swisscom Hospitality Services SA"}
{0x001267, "Matsushita Electronic Components Co."}
{0x001268, "IPS d.o.o."}
{0x001269, "Value Electronics"}
{0x00126a, "Optoelectronics Co."}
{0x00126b, "Ascalade Communications Limited"}
{0x00126c, "Visonic"}
{0x00126d, "University of California, Berkeley"}
{0x00126e, "Seidel Elektronik GmbH Nfg.KG"}
{0x00126f, "Rayson Technology Co."}
{0x001270, "Nges Denro Systems"}
{0x001271, "Measurement Computing"}
{0x001272, "Redux Communications"}
{0x001273, "Stoke"}
{0x001274, "NIT lab"}
{0x001275, "Sentilla"}
{0x001276, "CG Power Systems Ireland Limited"}
{0x001277, "Korenix Technologies Co."}
{0x001278, "International Bar Code"}
{0x001279, "Hewlett-Packard Company"}
{0x00127a, "Sanyu Industry Co."}
{0x00127b, "VIA Networking Technologies"}
{0x00127c, "Swegon AB"}
{0x00127d, "MobileAria"}
{0x00127e, "Digital Lifestyles Group"}
{0x00127f, "Cisco"}
{0x001280, "Cisco"}
{0x001281, "March Networks S.p.A."}
{0x001282, "Qovia"}
{0x001283, "Nortel Networks"}
{0x001284, "Lab33 Srl"}
{0x001285, "Gizmondo Europe"}
{0x001286, "Endevco"}
{0x001287, "Digital Everywhere Unterhaltungselektronik GmbH"}
{0x001288, "2Wire"}
{0x001289, "Advance Sterilization Products"}
{0x00128a, "Motorola Mobility"}
{0x00128b, "Sensory Networks"}
{0x00128c, "Woodward Governor"}
{0x00128d, "STB Datenservice GmbH"}
{0x00128e, "Q-Free ASA"}
{0x00128f, "Montilio"}
{0x001290, "Kyowa Electric & Machinery"}
{0x001291, "KWS Computersysteme GmbH"}
{0x001292, "Griffin Technology"}
{0x001293, "GE Energy"}
{0x001294, "Sumitomo Electric Device Innovations"}
{0x001295, "Aiware"}
{0x001296, "Addlogix"}
{0x001297, "O2Micro"}
{0x001298, "Mico Electric(shenzhen) Limited"}
{0x001299, "Ktech Telecommunications"}
{0x00129a, "IRT Electronics"}
{0x00129b, "E2S Electronic Engineering Solutions"}
{0x00129c, "Yulinet"}
{0x00129d, "First International Computer do Brasil"}
{0x00129e, "Surf Communications"}
{0x00129f, "RAE Systems"}
{0x0012a0, "NeoMeridian Sdn Bhd"}
{0x0012a1, "BluePacket Communications Co."}
{0x0012a2, "Vita"}
{0x0012a3, "Trust International B.V."}
{0x0012a4, "ThingMagic"}
{0x0012a5, "Stargen"}
{0x0012a6, "Dolby Australia"}
{0x0012a7, "ISR Technologies"}
{0x0012a8, "intec GmbH"}
{0x0012a9, "3Com"}
{0x0012aa, "IEE"}
{0x0012ab, "WiLife"}
{0x0012ac, "Ontimetek"}
{0x0012ad, "IDS GmbH"}
{0x0012ae, "HLS Hard-line Solutions"}
{0x0012af, "Elpro Technologies"}
{0x0012b0, "Efore Oyj   (Plc)"}
{0x0012b1, "Dai Nippon Printing Co."}
{0x0012b2, "Avolites"}
{0x0012b3, "Advance Wireless Technology"}
{0x0012b4, "Work Microwave GmbH"}
{0x0012b5, "Vialta"}
{0x0012b6, "Santa Barbara Infrared"}
{0x0012b7, "PTW Freiburg"}
{0x0012b8, "G2 Microsystems"}
{0x0012b9, "Fusion Digital Technology"}
{0x0012ba, "FSI Systems"}
{0x0012bb, "Telecommunications Industry Association TR-41 Committee"}
{0x0012bc, "Echolab"}
{0x0012bd, "Avantec Manufacturing Limited"}
{0x0012be, "Astek"}
{0x0012bf, "Arcadyan Technology"}
{0x0012c0, "HotLava Systems"}
{0x0012c1, "Check Point Software Technologies"}
{0x0012c2, "Apex Electronics Factory"}
{0x0012c3, "WIT S.A."}
{0x0012c4, "Viseon"}
{0x0012c5, "V-Show  Technology (China) Co."}
{0x0012c6, "TGC America"}
{0x0012c7, "Securay Technologiesco."}
{0x0012c8, "Perfect tech"}
{0x0012c9, "Motorola Mobility"}
{0x0012ca, "Mechatronic Brick Aps"}
{0x0012cb, "CSS"}
{0x0012cc, "Bitatek CO."}
{0x0012cd, "Asem SpA"}
{0x0012ce, "Advanced Cybernetics Group"}
{0x0012cf, "Accton Technology"}
{0x0012d0, "Gossen-Metrawatt-GmbH"}
{0x0012d1, "Texas Instruments"}
{0x0012d2, "Texas Instruments"}
{0x0012d3, "Zetta Systems"}
{0x0012d4, "Princeton Technology"}
{0x0012d5, "Motion Reality"}
{0x0012d6, "Jiangsu Yitong High-Tech Co."}
{0x0012d7, "Invento Networks"}
{0x0012d8, "International Games System Co."}
{0x0012d9, "Cisco Systems"}
{0x0012da, "Cisco Systems"}
{0x0012db, "Ziehl Industrie-elektronik Gmbh + Co KG"}
{0x0012dc, "SunCorp Industrial Limited"}
{0x0012dd, "Shengqu Information Technology (Shanghai) Co."}
{0x0012de, "Radio Components Sweden AB"}
{0x0012df, "Novomatic AG"}
{0x0012e0, "Codan Limited"}
{0x0012e1, "Alliant Networks"}
{0x0012e2, "Alaxala Networks"}
{0x0012e3, "Agat-RT"}
{0x0012e4, "Ziehl Industrie-electronik Gmbh + Co KG"}
{0x0012e5, "Time America"}
{0x0012e6, "Spectec Computer CO."}
{0x0012e7, "Projectek Networking Electronics"}
{0x0012e8, "Fraunhofer IMS"}
{0x0012e9, "Abbey Systems"}
{0x0012ea, "Trane"}
{0x0012eb, "R2DI"}
{0x0012ec, "Movacolor b.v."}
{0x0012ed, "AVG Advanced Technologies"}
{0x0012ee, "Sony Ericsson Mobile Communications AB"}
{0x0012ef, "OneAccess SA"}
{0x0012f0, "Intel Corporate"}
{0x0012f1, "Ifotec"}
{0x0012f2, "Brocade Communications Systems"}
{0x0012f3, "connectBlue AB"}
{0x0012f4, "Belco International Co."}
{0x0012f5, "Imarda New Zealand Limited"}
{0x0012f6, "MDK Co."}
{0x0012f7, "Xiamen Xinglian Electronics Co."}
{0x0012f8, "WNI Resources"}
{0x0012f9, "Uryu Seisaku"}
{0x0012fa, "THX"}
{0x0012fb, "Samsung Electronics"}
{0x0012fc, "Planet System Co."}
{0x0012fd, "Optimus IC S.A."}
{0x0012fe, "Lenovo Mobile Communication Technology"}
{0x0012ff, "Lely Industries N.V."}
{0x001300, "It-factory"}
{0x001301, "IronGate S.L."}
{0x001302, "Intel Corporate"}
{0x001303, "GateConnect Technologies GmbH"}
{0x001304, "Flaircomm Technologies Co."}
{0x001305, "Epicom"}
{0x001306, "Always On Wireless"}
{0x001307, "Paravirtual"}
{0x001308, "Nuvera Fuel Cells"}
{0x001309, "Ocean Broadband Networks"}
{0x00130a, "Nortel"}
{0x00130b, "Mextal B.V."}
{0x00130c, "HF System"}
{0x00130d, "Galileo Avionica"}
{0x00130e, "Focusrite Audio Engineering Limited"}
{0x00130f, "Egemen Bilgisayar Muh San ve Tic STI"}
{0x001310, "Cisco-Linksys"}
{0x001311, "Arris International"}
{0x001312, "Amedia Networks"}
{0x001313, "GuangZhou Post & Telecom Equipment"}
{0x001314, "Asiamajor"}
{0x001315, "Sony Computer Entertainment,"}
{0x001316, "L-S-B Broadcast Technologies GmbH"}
{0x001317, "GN Netcom as"}
{0x001318, "Dgstation Co."}
{0x001319, "Cisco Systems"}
{0x00131a, "Cisco Systems"}
{0x00131b, "BeCell Innovations"}
{0x00131c, "LiteTouch"}
{0x00131d, "Scanvaegt International A/S"}
{0x00131e, "Peiker acustic GmbH & Co. KG"}
{0x00131f, "NxtPhase T&D"}
{0x001320, "Intel Corporate"}
{0x001321, "Hewlett-Packard Company"}
{0x001322, "DAQ Electronics"}
{0x001323, "Cap Co."}
{0x001324, "Schneider Electric Ultra Terminal"}
{0x001325, "Cortina Systems"}
{0x001326, "ECM Systems"}
{0x001327, "Data Acquisitions limited"}
{0x001328, "Westech Korea,"}
{0x001329, "Vsst Co."}
{0x00132a, "Sitronics Telecom Solutions"}
{0x00132b, "Phoenix Digital"}
{0x00132c, "MAZ Brandenburg GmbH"}
{0x00132d, "iWise Communications"}
{0x00132e, "ITian Coporation"}
{0x00132f, "Interactek"}
{0x001330, "Euro Protection Surveillance"}
{0x001331, "CellPoint Connect"}
{0x001332, "Beijing Topsec Network Security Technology Co."}
{0x001333, "BaudTec"}
{0x001334, "Arkados"}
{0x001335, "VS Industry Berhad"}
{0x001336, "Tianjin 712 Communication Broadcasting co."}
{0x001337, "Orient Power Home Network"}
{0x001338, "Fresenius-vial"}
{0x001339, "El-me AG"}
{0x00133a, "VadaTech"}
{0x00133b, "Speed Dragon Multimedia Limited"}
{0x00133c, "Quintron Systems"}
{0x00133d, "Micro Memory Curtiss Wright Co"}
{0x00133e, "MetaSwitch"}
{0x00133f, "Eppendorf Instrumente GmbH"}
{0x001340, "AD.EL s.r.l."}
{0x001341, "Shandong New Beiyang Information Technology Co."}
{0x001342, "Vision Research"}
{0x001343, "Matsushita Electronic Components (Europe) GmbH"}
{0x001344, "Fargo Electronics"}
{0x001345, "Eaton"}
{0x001346, "D-Link"}
{0x001347, "BlueTree Wireless Data"}
{0x001348, "Artila Electronics Co."}
{0x001349, "ZyXEL Communications"}
{0x00134a, "Engim"}
{0x00134b, "ToGoldenNet Technology"}
{0x00134c, "YDT Technology International"}
{0x00134d, "IPC systems"}
{0x00134e, "Valox Systems"}
{0x00134f, "Tranzeo Wireless Technologies"}
{0x001350, "Silver Spring Networks"}
{0x001351, "Niles Audio"}
{0x001352, "Naztec"}
{0x001353, "Hydac Filtertechnik Gmbh"}
{0x001354, "Zcomax Technologies"}
{0x001355, "Tomen Cyber-business Solutions"}
{0x001356, "Flir Radiation Gmbh"}
{0x001357, "Soyal Technology Co."}
{0x001358, "Realm Systems"}
{0x001359, "ProTelevision Technologies A/S"}
{0x00135a, "Project T&E Limited"}
{0x00135b, "PanelLink Cinema"}
{0x00135c, "OnSite Systems"}
{0x00135d, "Nttpc Communications"}
{0x00135e, "Eab/rwi/k"}
{0x00135f, "Cisco Systems"}
{0x001360, "Cisco Systems"}
{0x001361, "Biospace Co."}
{0x001362, "ShinHeung Precision Co."}
{0x001363, "Verascape"}
{0x001364, "Paradigm Technology."}
{0x001365, "Nortel"}
{0x001366, "Neturity Technologies"}
{0x001367, "Narayon. Co."}
{0x001368, "Maersk Data Defence"}
{0x001369, "Honda Electron Co."}
{0x00136a, "Hach Lange SA"}
{0x00136b, "E-tec"}
{0x00136c, "TomTom"}
{0x00136d, "Tentaculus AB"}
{0x00136e, "Techmetro"}
{0x00136f, "PacketMotion"}
{0x001370, "Nokia Danmark A/S"}
{0x001371, "Motorola Mobility"}
{0x001372, "Dell"}
{0x001373, "BLwave Electronics Co."}
{0x001374, "Atheros Communications"}
{0x001375, "American Security Products Co."}
{0x001376, "Tabor Electronics"}
{0x001377, "Samsung Electronics CO."}
{0x001378, "Qsan Technology"}
{0x001379, "Ponder Information Industries"}
{0x00137a, "Netvox Technology Co."}
{0x00137b, "Movon"}
{0x00137c, "Kaicom co."}
{0x00137d, "Dynalab"}
{0x00137e, "CorEdge Networks"}
{0x00137f, "Cisco Systems"}
{0x001380, "Cisco Systems"}
{0x001381, "Chips & Systems"}
{0x001382, "Cetacea Networks"}
{0x001383, "Application Technologies and Engineering Research Laboratory"}
{0x001384, "Advanced Motion Controls"}
{0x001385, "Add-On Technology Co."}
{0x001386, "ABB/Totalflow"}
{0x001387, "27M Technologies AB"}
{0x001388, "WiMedia Alliance"}
{0x001389, "Redes de Telefona Mvil S.A."}
{0x00138a, "Qingdao Goertek Electronics Co."}
{0x00138b, "Phantom Technologies"}
{0x00138c, "Kumyoung.Co.Ltd"}
{0x00138d, "Kinghold"}
{0x00138e, "Foab Elektronik AB"}
{0x00138f, "Asiarock Incorporation"}
{0x001390, "Termtek Computer Co."}
{0x001391, "Ouen Co."}
{0x001392, "Ruckus Wireless"}
{0x001393, "Panta Systems"}
{0x001394, "Infohand Co."}
{0x001395, "congatec AG"}
{0x001396, "Acbel Polytech"}
{0x001397, "Xsigo Systems"}
{0x001398, "TrafficSim Co."}
{0x001399, "Stac"}
{0x00139a, "K-ubique ID"}
{0x00139b, "ioIMAGE"}
{0x00139c, "Exavera Technologies"}
{0x00139d, "Marvell Hispana S.L. "}
{0x00139e, "Ciara Technologies"}
{0x00139f, "Electronics Design Services, Co."}
{0x0013a0, "Algosystem Co."}
{0x0013a1, "Crow Electronic Engeneering"}
{0x0013a2, "MaxStream"}
{0x0013a3, "Siemens Com CPE Devices"}
{0x0013a4, "KeyEye Communications"}
{0x0013a5, "General Solutions"}
{0x0013a6, "Extricom"}
{0x0013a7, "Battelle Memorial Institute"}
{0x0013a8, "Tanisys Technology"}
{0x0013a9, "Sony"}
{0x0013aa, "ALS  & TEC"}
{0x0013ab, "Telemotive AG"}
{0x0013ac, "Sunmyung Electronics Co."}
{0x0013ad, "Sendo"}
{0x0013ae, "Radiance Technologies"}
{0x0013af, "Numa Technology"}
{0x0013b0, "Jablotron"}
{0x0013b1, "Intelligent Control Systems (Asia) Pte"}
{0x0013b2, "Carallon Limited"}
{0x0013b3, "Ecom Communications Technology Co."}
{0x0013b4, "Appear TV"}
{0x0013b5, "Wavesat"}
{0x0013b6, "Sling Media"}
{0x0013b7, "Scantech ID"}
{0x0013b8, "RyCo Electronic Systems Limited"}
{0x0013b9, "BM SPA"}
{0x0013ba, "ReadyLinks"}
{0x0013bb, "Smartvue"}
{0x0013bc, "Artimi"}
{0x0013bd, "Hymatom SA"}
{0x0013be, "Virtual Conexions"}
{0x0013bf, "Media System Planning"}
{0x0013c0, "Trix Tecnologia Ltda."}
{0x0013c1, "Asoka USA"}
{0x0013c2, "Wacom Co."}
{0x0013c3, "Cisco Systems"}
{0x0013c4, "Cisco Systems"}
{0x0013c5, "Lightron Fiber-optic Devices"}
{0x0013c6, "OpenGear"}
{0x0013c7, "Ionos Co."}
{0x0013c8, "ADB Broadband Italia"}
{0x0013c9, "Beyond Achieve Enterprises"}
{0x0013ca, "Pico Digital"}
{0x0013cb, "Zenitel Norway AS"}
{0x0013cc, "Tall Maple Systems"}
{0x0013cd, "MTI co."}
{0x0013ce, "Intel Corporate"}
{0x0013cf, "4Access Communications"}
{0x0013d0, "t+ Medical"}
{0x0013d1, "Kirk Telecom A/S"}
{0x0013d2, "Page Iberica"}
{0x0013d3, "Micro-star International CO."}
{0x0013d4, "Asustek Computer"}
{0x0013d5, "RuggedCom"}
{0x0013d6, "TII Network Technologies"}
{0x0013d7, "Spidcom Technologies SA"}
{0x0013d8, "Princeton Instruments"}
{0x0013d9, "Matrix Product Development"}
{0x0013da, "Diskware Co."}
{0x0013db, "Shoei Electric Co."}
{0x0013dc, "Ibtek"}
{0x0013dd, "Abbott Diagnostics"}
{0x0013de, "Adapt4"}
{0x0013df, "Ryvor"}
{0x0013e0, "Murata Manufacturing Co."}
{0x0013e1, "Iprobe AB"}
{0x0013e2, "GeoVision"}
{0x0013e3, "CoVi Technologies"}
{0x0013e4, "Yangjae Systems"}
{0x0013e5, "Tenosys"}
{0x0013e6, "Technolution"}
{0x0013e7, "Halcro"}
{0x0013e8, "Intel Corporate"}
{0x0013e9, "VeriWave"}
{0x0013ea, "Kamstrup A/S"}
{0x0013eb, "Sysmaster"}
{0x0013ec, "Sunbay Software AG"}
{0x0013ed, "Psia"}
{0x0013ee, "JBX Designs"}
{0x0013ef, "Kingjon Digital Technology Co."}
{0x0013f0, "Wavefront Semiconductor"}
{0x0013f1, "Amod Technology Co."}
{0x0013f2, "Klas"}
{0x0013f3, "Giga-byte Communications"}
{0x0013f4, "Psitek (Pty)"}
{0x0013f5, "Akimbi Systems"}
{0x0013f6, "Cintech"}
{0x0013f7, "SMC Networks"}
{0x0013f8, "Dex Security Solutions"}
{0x0013f9, "Cavera Systems"}
{0x0013fa, "LifeSize Communications"}
{0x0013fb, "RKC Instrument"}
{0x0013fc, "SiCortex"}
{0x0013fd, "Nokia Danmark A/S"}
{0x0013fe, "Grandtec Electronic"}
{0x0013ff, "Dage-MTI of MC"}
{0x001400, "Minerva Korea CO."}
{0x001401, "Rivertree Networks"}
{0x001402, "kk-electronic a/s"}
{0x001403, "Renasis"}
{0x001404, "Motorola Mobility"}
{0x001405, "OpenIB"}
{0x001406, "Go Networks"}
{0x001407, "Sperian Protection Instrumentation"}
{0x001408, "Eka Systems"}
{0x001409, "Magneti Marelli   S.E. S.p.a."}
{0x00140a, "Wepio Co."}
{0x00140b, "First International Computer"}
{0x00140c, "GKB Cctv CO."}
{0x00140d, "Nortel"}
{0x00140e, "Nortel"}
{0x00140f, "Federal State Unitary Enterprise Leningrad R&D Institute of"}
{0x001410, "Suzhou Keda Technology CO."}
{0x001411, "Deutschmann Automation GmbH & Co. KG"}
{0x001412, "S-TEC electronics AG"}
{0x001413, "Trebing & Himstedt Prozessautomation GmbH & Co. KG"}
{0x001414, "Jumpnode Systems"}
{0x001415, "Intec Automation"}
{0x001416, "Scosche Industries"}
{0x001417, "RSE Informations Technologie GmbH"}
{0x001418, "C4Line"}
{0x001419, "Sidsa"}
{0x00141a, "Deicy"}
{0x00141b, "Cisco Systems"}
{0x00141c, "Cisco Systems"}
{0x00141d, "Lust Antriebstechnik GmbH"}
{0x00141e, "P.A. Semi"}
{0x00141f, "SunKwang Electronics Co."}
{0x001420, "G-Links networking company"}
{0x001421, "Total Wireless Technologies Pte."}
{0x001422, "Dell"}
{0x001423, "J-S Co. Neurocom"}
{0x001424, "Merry Electrics CO."}
{0x001425, "Galactic Computing"}
{0x001426, "NL Technology"}
{0x001427, "JazzMutant"}
{0x001428, "Vocollect"}
{0x001429, "V Center Technologies Co."}
{0x00142a, "Elitegroup Computer System Co."}
{0x00142b, "Edata Communication"}
{0x00142c, "Koncept International"}
{0x00142d, "Toradex AG"}
{0x00142e, "77 Elektronika Kft."}
{0x00142f, "WildPackets"}
{0x001430, "ViPowER"}
{0x001431, "PDL Electronics"}
{0x001432, "Tarallax Wireless"}
{0x001433, "Empower Technologies(Canada)"}
{0x001434, "Keri Systems"}
{0x001435, "CityCom"}
{0x001436, "Qwerty Elektronik AB"}
{0x001437, "GSTeletech Co."}
{0x001438, "Hewlett-Packard Company"}
{0x001439, "Blonder Tongue Laboratories"}
{0x00143a, "Raytalk International SRL"}
{0x00143b, "Sensovation AG"}
{0x00143c, "Rheinmetall Canada"}
{0x00143d, "Aevoe"}
{0x00143e, "AirLink Communications"}
{0x00143f, "Hotway Technology"}
{0x001440, "Atomic"}
{0x001441, "Innovation Sound Technology Co."}
{0x001442, "Atto"}
{0x001443, "Consultronics Europe"}
{0x001444, "Grundfos Electronics"}
{0x001445, "Telefon-Gradnja d.o.o."}
{0x001446, "SuperVision Solutions"}
{0x001447, "Boaz"}
{0x001448, "Inventec Multimedia & Telecom"}
{0x001449, "Sichuan Changhong Electric"}
{0x00144a, "Taiwan Thick-Film Ind."}
{0x00144b, "Hifn"}
{0x00144c, "General Meters"}
{0x00144d, "Intelligent Systems"}
{0x00144e, "Srisa"}
{0x00144f, "Oracle"}
{0x001450, "Heim Systems GmbH"}
{0x001451, "Apple Computer"}
{0x001452, "Calculex"}
{0x001453, "Advantech Technologies Co."}
{0x001454, "Symwave"}
{0x001455, "Coder Electronics"}
{0x001456, "Edge Products"}
{0x001457, "T-vips AS"}
{0x001458, "HS Automatic ApS"}
{0x001459, "Moram Co."}
{0x00145a, "Neratec AG"}
{0x00145b, "SeekerNet"}
{0x00145c, "Intronics B.V."}
{0x00145d, "WJ Communications"}
{0x00145e, "IBM"}
{0x00145f, "Aditec CO."}
{0x001460, "Kyocera Wireless"}
{0x001461, "Corona"}
{0x001462, "Digiwell Technology"}
{0x001463, "Idcs N.V."}
{0x001464, "Cryptosoft"}
{0x001465, "Novo Nordisk A/S"}
{0x001466, "Kleinhenz Elektronik GmbH"}
{0x001467, "ArrowSpan"}
{0x001468, "CelPlan International"}
{0x001469, "Cisco Systems"}
{0x00146a, "Cisco Systems"}
{0x00146b, "Anagran"}
{0x00146c, "Netgear"}
{0x00146d, "RF Technologies"}
{0x00146e, "H. Stoll GmbH & Co. KG"}
{0x00146f, "Kohler Co"}
{0x001470, "Prokom Software SA"}
{0x001471, "Eastern Asia Technology Limited"}
{0x001472, "China Broadband Wireless IP Standard Group"}
{0x001473, "Bookham"}
{0x001474, "K40 Electronics"}
{0x001475, "Wiline Networks"}
{0x001476, "MultiCom Industries Limited"}
{0x001477, "Nertec "}
{0x001478, "Shenzhen Tp-link Technologies Co."}
{0x001479, "NEC Magnus Communications"}
{0x00147a, "Eubus GmbH"}
{0x00147b, "Iteris"}
{0x00147c, "3Com"}
{0x00147d, "Aeon Digital International"}
{0x00147e, "InnerWireless"}
{0x00147f, "Thomson Telecom Belgium"}
{0x001480, "Hitachi-LG Data Storage Korea"}
{0x001481, "Multilink"}
{0x001482, "GoBackTV"}
{0x001483, "eXS"}
{0x001484, "Cermate Technologies"}
{0x001485, "Giga-Byte"}
{0x001486, "Echo Digital Audio"}
{0x001487, "American Technology Integrators"}
{0x001488, "Akorri"}
{0x001489, "B15402100 - Jandei"}
{0x00148a, "Elin Ebg Traction Gmbh"}
{0x00148b, "Globo Electronic GmbH & Co. KG"}
{0x00148c, "Fortress Technologies"}
{0x00148d, "Cubic Defense Simulation Systems"}
{0x00148e, "Tele Power"}
{0x00148f, "Protronic (Far East)"}
{0x001490, "ASP"}
{0x001491, "Daniels Electronics"}
{0x001492, "Liteon, Mobile Media Solution SBU"}
{0x001493, "Systimax Solutions"}
{0x001494, "ESU AG"}
{0x001495, "2Wire"}
{0x001496, "Phonic"}
{0x001497, "Zhiyuan Eletronics Co."}
{0x001498, "Viking Design Technology"}
{0x001499, "Helicomm"}
{0x00149a, "Motorola Mobility"}
{0x00149b, "Nokota Communications"}
{0x00149c, "HF Company"}
{0x00149d, "Sound ID"}
{0x00149e, "UbONE Co."}
{0x00149f, "System and Chips"}
{0x0014a0, "Accsense"}
{0x0014a1, "Synchronous Communication"}
{0x0014a2, "Core Micro Systems"}
{0x0014a3, "Vitelec BV"}
{0x0014a4, "Hon Hai Precision Ind. Co."}
{0x0014a5, "Gemtek Technology Co."}
{0x0014a6, "Teranetics"}
{0x0014a7, "Nokia Danmark A/S"}
{0x0014a8, "Cisco Systems"}
{0x0014a9, "Cisco Systems"}
{0x0014aa, "Ashly Audio"}
{0x0014ab, "Senhai Electronic Technology Co."}
{0x0014ac, "Bountiful WiFi"}
{0x0014ad, "Gassner Wiege- u. Metechnik GmbH"}
{0x0014ae, "Wizlogics Co."}
{0x0014af, "Datasym"}
{0x0014b0, "Naeil Community"}
{0x0014b1, "Avitec AB"}
{0x0014b2, "mCubelogics"}
{0x0014b3, "CoreStar International"}
{0x0014b4, "General Dynamics United Kingdom"}
{0x0014b5, "Physiometrix"}
{0x0014b6, "Enswer Technology"}
{0x0014b7, "AR Infotek"}
{0x0014b8, "Hill-Rom"}
{0x0014b9, "Mstar Semiconductor"}
{0x0014ba, "Carvers SA de CV"}
{0x0014bb, "Open Interface North America"}
{0x0014bc, "Synectic Telecom Exports PVT."}
{0x0014bd, "incNETWORKS"}
{0x0014be, "Wink communication technologyLTD"}
{0x0014bf, "Cisco-Linksys"}
{0x0014c0, "Symstream Technology Group"}
{0x0014c1, "U.S. Robotics"}
{0x0014c2, "Hewlett-Packard Company"}
{0x0014c3, "Seagate Technology"}
{0x0014c4, "Vitelcom Mobile Technology"}
{0x0014c5, "Alive Technologies"}
{0x0014c6, "Quixant"}
{0x0014c7, "Nortel"}
{0x0014c8, "Contemporary Research"}
{0x0014c9, "Brocade Communications Systems"}
{0x0014ca, "Key Radio Systems Limited"}
{0x0014cb, "LifeSync"}
{0x0014cc, "Zetec"}
{0x0014cd, "DigitalZone Co."}
{0x0014ce, "NF"}
{0x0014cf, "Invisio Communications"}
{0x0014d0, "BTI Systems"}
{0x0014d1, "Trendnet"}
{0x0014d2, "Kyuden Technosystems"}
{0x0014d3, "Sepsa"}
{0x0014d4, "K Technology"}
{0x0014d5, "Datang Telecom Technology CO. , LCD,Optical Communication Br"}
{0x0014d6, "Jeongmin Electronics Co."}
{0x0014d7, "Datastore Technology"}
{0x0014d8, "bio-logic SA"}
{0x0014d9, "IP Fabrics"}
{0x0014da, "Huntleigh Healthcare"}
{0x0014db, "Elma Trenew Electronic GmbH"}
{0x0014dc, "Communication System Design & Manufacturing (csdm)"}
{0x0014dd, "Covergence"}
{0x0014de, "Sage Instruments"}
{0x0014df, "HI-P Tech"}
{0x0014e0, "LET'S"}
{0x0014e1, "Data Display AG"}
{0x0014e2, "datacom systems"}
{0x0014e3, "mm-lab GmbH"}
{0x0014e4, "Integral Technologies"}
{0x0014e5, "Alticast"}
{0x0014e6, "AIM Infrarotmodule GmbH"}
{0x0014e7, "Stolinx"}
{0x0014e8, "Motorola Mobility"}
{0x0014e9, "Nortech International"}
{0x0014ea, "S Digm (Safe Paradigm)"}
{0x0014eb, "AwarePoint"}
{0x0014ec, "Acro Telecom"}
{0x0014ed, "Airak"}
{0x0014ee, "Western Digital Technologies"}
{0x0014ef, "TZero Technologies"}
{0x0014f0, "Business Security OL AB"}
{0x0014f1, "Cisco Systems"}
{0x0014f2, "Cisco Systems"}
{0x0014f3, "ViXS Systems"}
{0x0014f4, "DekTec Digital Video B.V."}
{0x0014f5, "OSI Security Devices"}
{0x0014f6, "Juniper Networks"}
{0x0014f7, "Crevis"}
{0x0014f8, "Scientific Atlanta"}
{0x0014f9, "Vantage Controls"}
{0x0014fa, "AsGa S.A."}
{0x0014fb, "Technical Solutions"}
{0x0014fc, "Extandon"}
{0x0014fd, "Thecus Technology"}
{0x0014fe, "Artech Electronics"}
{0x0014ff, "Precise Automation"}
{0x001500, "Intel Corporate"}
{0x001501, "LexBox"}
{0x001502, "Beta Tech"}
{0x001503, "Proficomms S.r.o."}
{0x001504, "Game Plus CO."}
{0x001505, "Actiontec Electronics"}
{0x001506, "Neo Photonics"}
{0x001507, "Renaissance Learning"}
{0x001508, "Global Target Enterprise"}
{0x001509, "Plus Technology Co."}
{0x00150a, "Sonoa Systems"}
{0x00150b, "Sage Infotech"}
{0x00150c, "AVM GmbH"}
{0x00150d, "Hoana Medical"}
{0x00150e, "Openbrain Technologies CO."}
{0x00150f, "mingjong"}
{0x001510, "Techsphere Co."}
{0x001511, "Data Center Systems"}
{0x001512, "Zurich University of Applied Sciences"}
{0x001513, "EFS sas"}
{0x001514, "Hu Zhou Nava Networks&electronics"}
{0x001515, "Leipold+Co.GmbH"}
{0x001516, "Uriel Systems"}
{0x001517, "Intel Corporate"}
{0x001518, "Shenzhen 10MOONS Technology Development CO."}
{0x001519, "StoreAge Networking Technologies"}
{0x00151a, "Hunter Engineering Company"}
{0x00151b, "Isilon Systems"}
{0x00151c, "Leneco"}
{0x00151d, "M2I"}
{0x00151e, "Ethernet Powerlink Standardization Group (epsg)"}
{0x00151f, "Multivision Intelligent Surveillance (Hong Kong)"}
{0x001520, "Radiocrafts AS"}
{0x001521, "Horoquartz"}
{0x001522, "Dea Security"}
{0x001523, "Meteor Communications"}
{0x001524, "Numatics"}
{0x001525, "Chamberlain Access Solutions"}
{0x001526, "Remote Technologies"}
{0x001527, "Balboa Instruments"}
{0x001528, "Beacon Medical Products d.b.a. BeaconMedaes"}
{0x001529, "N3"}
{0x00152a, "Nokia GmbH"}
{0x00152b, "Cisco Systems"}
{0x00152c, "Cisco Systems"}
{0x00152d, "TenX Networks"}
{0x00152e, "PacketHop"}
{0x00152f, "Motorola Mobility"}
{0x001530, "Bus-Tech"}
{0x001531, "Kocom"}
{0x001532, "Consumer Technologies Group"}
{0x001533, "Nadam.co."}
{0x001534, "A Beltrnica, Companhia de Comunicaes"}
{0x001535, "OTE Spa"}
{0x001536, "Powertech co."}
{0x001537, "Ventus Networks"}
{0x001538, "RFID"}
{0x001539, "Technodrive SRL"}
{0x00153a, "Shenzhen Syscan Technology Co."}
{0x00153b, "EMH metering GmbH & Co. KG"}
{0x00153c, "Kprotech Co."}
{0x00153d, "Elim Product CO."}
{0x00153e, "Q-Matic Sweden AB"}
{0x00153f, "Alcatel Alenia Space Italia"}
{0x001540, "Nortel"}
{0x001541, "StrataLight Communications"}
{0x001542, "Microhard S.r.l."}
{0x001543, "Aberdeen Test Center"}
{0x001544, "coM.s.a.t. AG"}
{0x001545, "Seecode Co."}
{0x001546, "ITG Worldwide Sdn Bhd"}
{0x001547, "AiZen Solutions"}
{0x001548, "Cube Technologies"}
{0x001549, "Dixtal Biomedica Ind. Com. Ltda"}
{0x00154a, "Wanshih Electronic CO."}
{0x00154b, "Wonde Proud Technology Co."}
{0x00154c, "Saunders Electronics"}
{0x00154d, "Netronome Systems"}
{0x00154e, "IEC"}
{0x00154f, "one RF Technology"}
{0x001550, "Nits Technology"}
{0x001551, "RadioPulse"}
{0x001552, "Wi-Gear"}
{0x001553, "Cytyc"}
{0x001554, "Atalum Wireless S.A."}
{0x001555, "DFM GmbH"}
{0x001556, "Sagem Communication"}
{0x001557, "Olivetti"}
{0x001558, "Foxconn"}
{0x001559, "Securaplane Technologies"}
{0x00155a, "Dainippon Pharmaceutical CO."}
{0x00155b, "Sampo"}
{0x00155c, "Dresser Wayne"}
{0x00155d, "Microsoft"}
{0x00155e, "Morgan Stanley"}
{0x00155f, "GreenPeak Technologies"}
{0x001560, "Hewlett-Packard Company"}
{0x001561, "JJPlus"}
{0x001562, "Cisco Systems"}
{0x001563, "Cisco Systems"}
{0x001564, "Behringer Spezielle Studiotechnik Gmbh"}
{0x001565, "Xiamen Yealink Network Technology Co."}
{0x001566, "A-First Technology Co."}
{0x001567, "Radwin"}
{0x001568, "Dilithium Networks"}
{0x001569, "Peco II"}
{0x00156a, "DG2L Technologies Pvt."}
{0x00156b, "Perfisans Networks"}
{0x00156c, "Sane System CO."}
{0x00156d, "Ubiquiti Networks"}
{0x00156e, "A. W. Communication Systems"}
{0x00156f, "Xiranet Communications GmbH"}
{0x001570, "Symbol TechnologiesWholly owned Subsidiary of Motorola"}
{0x001571, "Nolan Systems"}
{0x001572, "Red-Lemon"}
{0x001573, "NewSoft  Technology"}
{0x001574, "Horizon Semiconductors"}
{0x001575, "Nevis Networks"}
{0x001576, "scil animal care company GmbH"}
{0x001577, "Allied Telesis"}
{0x001578, "Audio / Video Innovations"}
{0x001579, "Lunatone Industrielle Elektronik GmbH"}
{0x00157a, "Telefin S.p.A."}
{0x00157b, "Leuze electronic GmbH + Co. KG"}
{0x00157c, "Dave Networks"}
{0x00157d, "Posdata CO."}
{0x00157e, "Weidmller Interface GmbH & Co. KG"}
{0x00157f, "ChuanG International Holding CO."}
{0x001580, "U-way"}
{0x001581, "Makus"}
{0x001582, "TVonics"}
{0x001583, "IVT"}
{0x001584, "Schenck Process GmbH"}
{0x001585, "Aonvision Technolopy"}
{0x001586, "Xiamen Overseas Chinese Electronic Co."}
{0x001587, "Takenaka Seisakusho Co."}
{0x001588, "Balda Solution Malaysia Sdn Bhd"}
{0x001589, "D-MAX Technology Co."}
{0x00158a, "Surecom Technology"}
{0x00158b, "Park Air Systems"}
{0x00158c, "Liab ApS"}
{0x00158d, "Jennic"}
{0x00158e, "Plustek.INC"}
{0x00158f, "NTT Advanced Technology"}
{0x001590, "Hectronic GmbH"}
{0x001591, "RLW"}
{0x001592, "Facom UK (Melksham)"}
{0x001593, "U4EA Technologies"}
{0x001594, "Bixolon Co."}
{0x001595, "Quester Tangent"}
{0x001596, "Arris International"}
{0x001597, "Aeta Audio Systems"}
{0x001598, "Kolektor group"}
{0x001599, "Samsung Electronics Co."}
{0x00159a, "Motorola Mobility"}
{0x00159b, "Nortel"}
{0x00159c, "B-kyung System Co."}
{0x00159d, "Minicom Advanced Systems"}
{0x00159e, "Mad Catz Interactive"}
{0x00159f, "Terascala"}
{0x0015a0, "Nokia Danmark A/S"}
{0x0015a1, "Eca-sinters"}
{0x0015a2, "Arris International"}
{0x0015a3, "Arris International"}
{0x0015a4, "Arris International"}
{0x0015a5, "DCI Co."}
{0x0015a6, "Digital Electronics Products"}
{0x0015a7, "Robatech AG"}
{0x0015a8, "Motorola Mobility"}
{0x0015a9, "Kwang WOO I&C Co."}
{0x0015aa, "Rextechnik International Co.,"}
{0x0015ab, "PRO CO Sound"}
{0x0015ac, "Capelon AB"}
{0x0015ad, "Accedian Networks"}
{0x0015ae, "kyung il"}
{0x0015af, "AzureWave Technologies"}
{0x0015b0, "Autotelenet Co."}
{0x0015b1, "Ambient"}
{0x0015b2, "Advanced Industrial Computer"}
{0x0015b3, "Caretech AB"}
{0x0015b4, "Polymap  Wireless"}
{0x0015b5, "CI Network"}
{0x0015b6, "ShinMaywa Industries"}
{0x0015b7, "Toshiba"}
{0x0015b8, "Tahoe"}
{0x0015b9, "Samsung Electronics Co."}
{0x0015ba, "iba AG"}
{0x0015bb, "SMA Solar Technology AG"}
{0x0015bc, "Develco"}
{0x0015bd, "Group 4 Technology"}
{0x0015be, "Iqua"}
{0x0015bf, "technicob"}
{0x0015c0, "Digital Telemedia Co."}
{0x0015c1, "Sony Computer Entertainment,"}
{0x0015c2, "3M Germany"}
{0x0015c3, "Ruf Telematik AG"}
{0x0015c4, "Flovel CO."}
{0x0015c5, "Dell"}
{0x0015c6, "Cisco Systems"}
{0x0015c7, "Cisco Systems"}
{0x0015c8, "FlexiPanel"}
{0x0015c9, "Gumstix"}
{0x0015ca, "TeraRecon"}
{0x0015cb, "Surf Communication Solutions"}
{0x0015cc, "Tepco Uquest"}
{0x0015cd, "Exartech International"}
{0x0015ce, "Arris International"}
{0x0015cf, "Arris International"}
{0x0015d0, "Arris International"}
{0x0015d1, "Arris Group"}
{0x0015d2, "Xantech"}
{0x0015d3, "Pantech&Curitel Communications"}
{0x0015d4, "Emitor AB"}
{0x0015d5, "Nicevt"}
{0x0015d6, "OSLiNK Sp. z o.o."}
{0x0015d7, "Reti"}
{0x0015d8, "Interlink Electronics"}
{0x0015d9, "PKC Electronics Oy"}
{0x0015da, "Iritel A.D."}
{0x0015db, "Canesta"}
{0x0015dc, "KT&C Co."}
{0x0015dd, "IP Control Systems"}
{0x0015de, "Nokia Danmark A/S"}
{0x0015df, "Clivet S.p.A."}
{0x0015e0, "ST-Ericsson"}
{0x0015e1, "Picochip"}
{0x0015e2, "Dr.Ing. Herbert Knauer GmbH"}
{0x0015e3, "Dream Technologies"}
{0x0015e4, "Zimmer Elektromedizin"}
{0x0015e5, "Cheertek"}
{0x0015e6, "Mobile Technika"}
{0x0015e7, "Quantec ProAudio"}
{0x0015e8, "Nortel"}
{0x0015e9, "D-Link"}
{0x0015ea, "Tellumat (Pty)"}
{0x0015eb, "ZTE"}
{0x0015ec, "Boca Devices"}
{0x0015ed, "Fulcrum Microsystems"}
{0x0015ee, "Omnex Control Systems"}
{0x0015ef, "NEC Tokin"}
{0x0015f0, "EGO BV"}
{0x0015f1, "Kylink Communications"}
{0x0015f2, "Asustek Computer"}
{0x0015f3, "Peltor AB"}
{0x0015f4, "Eventide"}
{0x0015f5, "Sustainable Energy Systems"}
{0x0015f6, "Science AND Engineering Services"}
{0x0015f7, "Wintecronics"}
{0x0015f8, "Kingtronics Industrial Co."}
{0x0015f9, "Cisco Systems"}
{0x0015fa, "Cisco Systems"}
{0x0015fb, "setex schermuly textile computer gmbh"}
{0x0015fc, "Littelfuse Startco"}
{0x0015fd, "Complete Media Systems"}
{0x0015fe, "Schilling Robotics"}
{0x0015ff, "Novatel Wireless"}
{0x001600, "CelleBrite Mobile Synchronization"}
{0x001601, "Buffalo"}
{0x001602, "Ceyon Technology Co."}
{0x001603, "Coolksky Co."}
{0x001604, "Sigpro"}
{0x001605, "Yorkville Sound"}
{0x001606, "Ideal Industries"}
{0x001607, "Curves International"}
{0x001608, "Sequans Communications"}
{0x001609, "Unitech electronics co."}
{0x00160a, "Sweex Europe BV"}
{0x00160b, "TVWorks"}
{0x00160c, "LPL  Development S.A. DE C.V"}
{0x00160d, "Be Here"}
{0x00160e, "Optica Technologies"}
{0x00160f, "Badger Meter"}
{0x001610, "Carina Technology"}
{0x001611, "Altecon Srl"}
{0x001612, "Otsuka Electronics Co."}
{0x001613, "LibreStream Technologies"}
{0x001614, "Picosecond Pulse Labs"}
{0x001615, "Nittan Company, Limited"}
{0x001616, "Browan Communication"}
{0x001617, "MSI"}
{0x001618, "Hivion Co."}
{0x001619, "La Factora de Comunicaciones Aplicadas"}
{0x00161a, "Dametric AB"}
{0x00161b, "Micronet"}
{0x00161c, "e:cue"}
{0x00161d, "Innovative Wireless Technologies"}
{0x00161e, "Woojinnet"}
{0x00161f, "Sunwavetec Co."}
{0x001620, "Sony Ericsson Mobile Communications AB"}
{0x001621, "Colorado Vnet"}
{0x001622, "BBH Systems Gmbh"}
{0x001623, "Interval Media"}
{0x001624, "Teneros"}
{0x001625, "Impinj"}
{0x001626, "Motorola Mobility"}
{0x001627, "Embedded-logic Design AND More Gmbh"}
{0x001628, "Ultra Electronics Manufacturing and Card Systems"}
{0x001629, "Nivus GmbH"}
{0x00162a, "Antik computers & communications s.r.o."}
{0x00162b, "Togami Electric Mfg.co."}
{0x00162c, "Xanboo"}
{0x00162d, "STNet Co."}
{0x00162e, "Space Shuttle Hi-Tech Co."}
{0x00162f, "Geutebrck GmbH"}
{0x001630, "Vativ Technologies"}
{0x001631, "Xteam"}
{0x001632, "Samsung Electronics CO."}
{0x001633, "Oxford Diagnostics"}
{0x001634, "Mathtech"}
{0x001635, "Hewlett-Packard Company"}
{0x001636, "Quanta Computer"}
{0x001637, "Citel Srl"}
{0x001638, "Tecom Co."}
{0x001639, "Ubiquam Co."}
{0x00163a, "Yves Technology CO."}
{0x00163b, "VertexRSI/General Dynamics"}
{0x00163c, "Rebox B.V."}
{0x00163d, "Tsinghua Tongfang Legend Silicon Tech. Co."}
{0x00163e, "Xensource"}
{0x00163f, "Crete Systems"}
{0x001640, "Asmobile Communication"}
{0x001641, "Universal Global Scientific Industrial Co."}
{0x001642, "Pangolin"}
{0x001643, "Sunhillo"}
{0x001644, "Lite-on Technology"}
{0x001645, "Power Distribution"}
{0x001646, "Cisco Systems"}
{0x001647, "Cisco Systems"}
{0x001648, "SSD Company Limited"}
{0x001649, "SetOne GmbH"}
{0x00164a, "Vibration Technology Limited"}
{0x00164b, "Quorion Data Systems GmbH"}
{0x00164c, "Planet INT Co."}
{0x00164d, "Alcatel North America IP Division"}
{0x00164e, "Nokia Danmark A/S"}
{0x00164f, "World Ethnic Broadcastin"}
{0x001650, "Herley General Microwave Israel. "}
{0x001651, "Exeo Systems"}
{0x001652, "Hoatech Technologies"}
{0x001653, "Lego System A/S IE Electronics Division"}
{0x001654, "Flex-P Industries Sdn. Bhd."}
{0x001655, "Fuho Technology Co."}
{0x001656, "Nintendo Co."}
{0x001657, "Aegate"}
{0x001658, "Fusiontech Technologies"}
{0x001659, "Z.m.p. Radwag"}
{0x00165a, "Harman Specialty Group"}
{0x00165b, "Grip Audio"}
{0x00165c, "Trackflow"}
{0x00165d, "AirDefense"}
{0x00165e, "Precision I/O"}
{0x00165f, "Fairmount Automation"}
{0x001660, "Nortel"}
{0x001661, "Novatium Solutions (P)"}
{0x001662, "Liyuh Technology"}
{0x001663, "KBT Mobile"}
{0x001664, "Prod-El SpA"}
{0x001665, "Cellon France"}
{0x001666, "Quantier Communication"}
{0x001667, "A-TEC Subsystem"}
{0x001668, "Eishin Electronics"}
{0x001669, "MRV Communication (Networks)"}
{0x00166a, "TPS"}
{0x00166b, "Samsung Electronics"}
{0x00166c, "Samsung Electonics Digital Video System Division"}
{0x00166d, "Yulong Computer Telecommunication Scientific(shenzhen)Co."}
{0x00166e, "Arbitron"}
{0x00166f, "Intel"}
{0x001670, "Sknet"}
{0x001671, "Symphox Information Co."}
{0x001672, "Zenway enterprise"}
{0x001673, "Bury GmbH & Co. KG"}
{0x001674, "EuroCB (Phils.)"}
{0x001675, "Motorola Mobility"}
{0x001676, "Intel"}
{0x001677, "Bihl+Wiedemann GmbH"}
{0x001678, "Shenzhen Baoan Gaoke Electronics CO."}
{0x001679, "eOn Communications"}
{0x00167a, "Skyworth Overseas Dvelopment"}
{0x00167b, "Haver&Boecker"}
{0x00167c, "iRex Technologies BV"}
{0x00167d, "Sky-Line Information Co."}
{0x00167e, "Diboss.co."}
{0x00167f, "Bluebird Soft"}
{0x001680, "Bally Gaming + Systems"}
{0x001681, "Vector Informatik GmbH"}
{0x001682, "Pro Dex"}
{0x001683, "Webio International Co."}
{0x001684, "Donjin Co."}
{0x001685, "Elisa Oyj"}
{0x001686, "Karl Storz Imaging"}
{0x001687, "Chubb CSC-Vendor AP"}
{0x001688, "ServerEngines"}
{0x001689, "Pilkor Electronics Co."}
{0x00168a, "id-Confirm"}
{0x00168b, "Paralan"}
{0x00168c, "DSL Partner AS"}
{0x00168d, "Korwin CO."}
{0x00168e, "Vimicro"}
{0x00168f, "GN Netcom as"}
{0x001690, "J-tek Incorporation"}
{0x001691, "Moser-Baer AG"}
{0x001692, "Scientific-Atlanta"}
{0x001693, "PowerLink Technology"}
{0x001694, "Sennheiser Communications A/S"}
{0x001695, "AVC Technology Limited"}
{0x001696, "QDI Technology (H.K.) Limited"}
{0x001697, "NEC"}
{0x001698, "T&A Mobile Phones"}
{0x001699, "Tonic DVB Marketing"}
{0x00169a, "Quadrics"}
{0x00169b, "Alstom Transport"}
{0x00169c, "Cisco Systems"}
{0x00169d, "Cisco Systems"}
{0x00169e, "TV One"}
{0x00169f, "Vimtron Electronics Co."}
{0x0016a0, "Auto-Maskin"}
{0x0016a1, "3Leaf Networks"}
{0x0016a2, "CentraLite Systems"}
{0x0016a3, "Ingeteam Transmission&Distribution"}
{0x0016a4, "Ezurio"}
{0x0016a5, "Tandberg Storage ASA"}
{0x0016a6, "Dovado FZ-LLC"}
{0x0016a7, "Aweta G&P"}
{0x0016a8, "CWT CO."}
{0x0016a9, "2EI"}
{0x0016aa, "Kei Communication Technology"}
{0x0016ab, "PBI-Dansensor A/S"}
{0x0016ac, "Toho Technology"}
{0x0016ad, "BT-Links Company Limited"}
{0x0016ae, "Inventel"}
{0x0016af, "Shenzhen Union Networks Equipment Co."}
{0x0016b0, "VK"}
{0x0016b1, "KBS"}
{0x0016b2, "DriveCam"}
{0x0016b3, "Photonicbridges (China) Co."}
{0x0016b4, "Private"}
{0x0016b5, "Motorola Mobility"}
{0x0016b6, "Cisco-Linksys"}
{0x0016b7, "Seoul Commtech"}
{0x0016b8, "Sony Ericsson Mobile Communications"}
{0x0016b9, "ProCurve Networking"}
{0x0016ba, "Weathernews"}
{0x0016bb, "Law-Chain Computer Technology Co"}
{0x0016bc, "Nokia Danmark A/S"}
{0x0016bd, "ATI Industrial Automation"}
{0x0016be, "Infranet"}
{0x0016bf, "PaloDEx Group Oy"}
{0x0016c0, "Semtech"}
{0x0016c1, "Eleksen"}
{0x0016c2, "Avtec Systems"}
{0x0016c3, "BA Systems"}
{0x0016c4, "SiRF Technology"}
{0x0016c5, "Shenzhen Xing Feng Industry Co."}
{0x0016c6, "North Atlantic Industries"}
{0x0016c7, "Cisco Systems"}
{0x0016c8, "Cisco Systems"}
{0x0016c9, "NAT Seattle"}
{0x0016ca, "Nortel"}
{0x0016cb, "Apple Computer"}
{0x0016cc, "Xcute Mobile"}
{0x0016cd, "Hiji High-tech CO."}
{0x0016ce, "Hon Hai Precision Ind. Co."}
{0x0016cf, "Hon Hai Precision Ind. Co."}
{0x0016d0, "ATech elektronika d.o.o."}
{0x0016d1, "ZAT a.s."}
{0x0016d2, "Caspian"}
{0x0016d3, "Wistron"}
{0x0016d4, "Compal Communications"}
{0x0016d5, "Synccom Co."}
{0x0016d6, "TDA Tech"}
{0x0016d7, "Sunways AG"}
{0x0016d8, "Senea AB"}
{0x0016d9, "Ningbo Bird Co."}
{0x0016da, "Futronic Technology Co."}
{0x0016db, "Samsung Electronics Co."}
{0x0016dc, "Archos"}
{0x0016dd, "Gigabeam"}
{0x0016de, "Fast"}
{0x0016df, "Lundinova AB"}
{0x0016e0, "3Com"}
{0x0016e1, "SiliconStor"}
{0x0016e2, "American Fibertek"}
{0x0016e3, "Askey Computer"}
{0x0016e4, "Vanguard Security Engineering"}
{0x0016e5, "Fordley Development Limited"}
{0x0016e6, "Giga-byte Technology Co."}
{0x0016e7, "Dynamix Promotions Limited"}
{0x0016e8, "Sigma Designs"}
{0x0016e9, "Tiba Medical"}
{0x0016ea, "Intel"}
{0x0016eb, "Intel"}
{0x0016ec, "Elitegroup Computer Systems Co."}
{0x0016ed, "Digital Safety Technologies"}
{0x0016ee, "RoyalDigital"}
{0x0016ef, "Koko Fitness"}
{0x0016f0, "Dell"}
{0x0016f1, "OmniSense"}
{0x0016f2, "Dmobile System Co."}
{0x0016f3, "Cast Information Co."}
{0x0016f4, "Eidicom Co."}
{0x0016f5, "Dalian Golden Hualu Digital Technology Co."}
{0x0016f6, "Video Products Group"}
{0x0016f7, "L-3 Communications, Electrodynamics"}
{0x0016f8, "Aviqtech Technology CO."}
{0x0016f9, "Cetrta POT, D.o.o."}
{0x0016fa, "ECI Telecom"}
{0x0016fb, "Shenzhen MTC Co."}
{0x0016fc, "Tohken Co."}
{0x0016fd, "Jaty Electronics"}
{0x0016fe, "Alps Electric Co."}
{0x0016ff, "Wamin Optocomm Mfg"}
{0x001700, "Motorola Mobility"}
{0x001701, "KDE"}
{0x001702, "Osung Midicom Co."}
{0x001703, "Mosdan Internation Co."}
{0x001704, "Shinco Electronics Group Co."}
{0x001705, "Methode Electronics"}
{0x001706, "Techfaith Wireless Communication Technology Limited."}
{0x001707, "InGrid"}
{0x001708, "Hewlett-Packard Company"}
{0x001709, "Exalt Communications"}
{0x00170a, "Inew Digital Company"}
{0x00170b, "Contela"}
{0x00170c, "Twig Com "}
{0x00170d, "Dust Networks"}
{0x00170e, "Cisco Systems"}
{0x00170f, "Cisco Systems"}
{0x001710, "Casa Systems"}
{0x001711, "GE Healthcare Bio-Sciences AB"}
{0x001712, "Isco International"}
{0x001713, "Tiger NetCom"}
{0x001714, "BR Controls Nederland bv"}
{0x001715, "Qstik"}
{0x001716, "Qno Technology"}
{0x001717, "Leica Geosystems AG"}
{0x001718, "Vansco Electronics Oy"}
{0x001719, "AudioCodes USA"}
{0x00171a, "Winegard Company"}
{0x00171b, "Innovation Lab"}
{0x00171c, "NT MicroSystems"}
{0x00171d, "Digit"}
{0x00171e, "Theo Benning GmbH & Co. KG"}
{0x00171f, "IMV"}
{0x001720, "Image Sensing Systems"}
{0x001721, "Fitre S.p.a."}
{0x001722, "Hanazeder Electronic GmbH"}
{0x001723, "Summit Data Communications"}
{0x001724, "Studer Professional Audio GmbH"}
{0x001725, "Liquid Computing"}
{0x001726, "m2c Electronic Technology"}
{0x001727, "Thermo Ramsey Italia s.r.l."}
{0x001728, "Selex Communications"}
{0x001729, "UbicodLTD"}
{0x00172a, "Proware Technology"}
{0x00172b, "Global Technologies"}
{0x00172c, "Taejin Infotech"}
{0x00172d, "Axcen Photonics"}
{0x00172e, "FXC"}
{0x00172f, "NeuLion Incorporated"}
{0x001730, "Automation Electronics"}
{0x001731, "Asustek Computer"}
{0x001732, "Science-technical Center "rissa""}
{0x001733, "SFR"}
{0x001734, "ADC Telecommunications"}
{0x001735, "Private"}
{0x001736, "iiTron"}
{0x001737, "Industrie Dial Face S.p.A."}
{0x001738, "International Business Machines"}
{0x001739, "Bright Headphone Electronics Company"}
{0x00173a, "Reach Systems"}
{0x00173b, "Cisco Systems"}
{0x00173c, "Extreme Engineering Solutions"}
{0x00173d, "Neology"}
{0x00173e, "LeucotronEquipamentos Ltda."}
{0x00173f, "Belkin"}
{0x001740, "Bluberi Gaming Technologies"}
{0x001741, "Defidev"}
{0x001742, "Fujitsu Limited"}
{0x001743, "Deck Srl"}
{0x001744, "Araneo"}
{0x001745, "Innotz CO."}
{0x001746, "Freedom9"}
{0x001747, "Trimble"}
{0x001748, "Neokoros Brasil Ltda"}
{0x001749, "Hyundae Yong-o-sa Co."}
{0x00174a, "Socomec"}
{0x00174b, "Nokia Danmark A/S"}
{0x00174c, "Millipore"}
{0x00174d, "Dynamic Network Factory"}
{0x00174e, "Parama-tech Co."}
{0x00174f, "iCatch"}
{0x001750, "GSI Group, MicroE Systems"}
{0x001751, "Online"}
{0x001752, "DAGS"}
{0x001753, "nFore Technology"}
{0x001754, "Arkino HiTOP Limited"}
{0x001755, "GE Security"}
{0x001756, "Vinci Labs Oy"}
{0x001757, "RIX Technology Limited"}
{0x001758, "ThruVision"}
{0x001759, "Cisco Systems"}
{0x00175a, "Cisco Systems"}
{0x00175b, "ACS Solutions Switzerland"}
{0x00175c, "Sharp"}
{0x00175d, "Dongseo system."}
{0x00175e, "Zed-3"}
{0x00175f, "Xenolink Communications Co."}
{0x001760, "Naito Densei Machida MFG.CO."}
{0x001761, "ZKSoftware"}
{0x001762, "Solar Technology"}
{0x001763, "Essentia S.p.A."}
{0x001764, "ATMedia GmbH"}
{0x001765, "Nortel"}
{0x001766, "Accense Technology"}
{0x001767, "Earforce AS"}
{0x001768, "Zinwave"}
{0x001769, "Cymphonix"}
{0x00176a, "Avago Technologies"}
{0x00176b, "Kiyon"}
{0x00176c, "Pivot3"}
{0x00176d, "Core"}
{0x00176e, "Ducati Sistemi"}
{0x00176f, "PAX Computer Technology(Shenzhen)"}
{0x001770, "Arti Industrial Electronics"}
{0x001771, "APD Communications"}
{0x001772, "Astro Strobel Kommunikationssysteme Gmbh"}
{0x001773, "Laketune Technologies Co."}
{0x001774, "Elesta GmbH"}
{0x001775, "TTE Germany GmbH"}
{0x001776, "Meso Scale Diagnostics"}
{0x001777, "Obsidian Research"}
{0x001778, "Central Music Co."}
{0x001779, "QuickTel"}
{0x00177a, "Assa Abloy AB"}
{0x00177b, "Azalea Networks"}
{0x00177c, "Smartlink Network Systems Limited"}
{0x00177d, "IDT International Limited"}
{0x00177e, "Meshcom Technologies"}
{0x00177f, "Worldsmart Retech"}
{0x001780, "Applied Biosystems B.V."}
{0x001781, "Greystone Data System"}
{0x001782, "LoBenn"}
{0x001783, "Texas Instruments"}
{0x001784, "Motorola Mobility"}
{0x001785, "Sparr Electronics"}
{0x001786, "wisembed"}
{0x001787, "Brother, Brother & Sons ApS"}
{0x001788, "Philips Lighting BV"}
{0x001789, "Zenitron"}
{0x00178a, "Darts Technologies"}
{0x00178b, "Teledyne Technologies Incorporated"}
{0x00178c, "Independent Witness"}
{0x00178d, "Checkpoint Systems"}
{0x00178e, "Gunnebo Cash Automation AB"}
{0x00178f, "Ningbo Yidong Electronic Co."}
{0x001790, "Hyundai Digitech Co"}
{0x001791, "LinTech GmbH"}
{0x001792, "Falcom Wireless Comunications Gmbh"}
{0x001793, "Tigi"}
{0x001794, "Cisco Systems"}
{0x001795, "Cisco Systems"}
{0x001796, "Rittmeyer AG"}
{0x001797, "Telsy Elettronica S.p.A."}
{0x001798, "Azonic Technology Co."}
{0x001799, "SmarTire Systems"}
{0x00179a, "D-Link"}
{0x00179b, "Chant Sincere CO."}
{0x00179c, "Deprag Schulz Gmbh u. CO."}
{0x00179d, "Kelman Limited"}
{0x00179e, "Sirit"}
{0x00179f, "Apricorn"}
{0x0017a0, "RoboTech srl"}
{0x0017a1, "3soft"}
{0x0017a2, "Camrivox"}
{0x0017a3, "MIX s.r.l."}
{0x0017a4, "Hewlett-Packard Company"}
{0x0017a5, "Ralink Technology"}
{0x0017a6, "Yosin Electronics CO."}
{0x0017a7, "Mobile Computing Promotion Consortium"}
{0x0017a8, "EDM"}
{0x0017a9, "Sentivision"}
{0x0017aa, "elab-experience"}
{0x0017ab, "Nintendo Co."}
{0x0017ac, "O'Neil Product Development"}
{0x0017ad, "AceNet"}
{0x0017ae, "GAI-Tronics"}
{0x0017af, "Enermet"}
{0x0017b0, "Nokia Danmark A/S"}
{0x0017b1, "Acist Medical Systems"}
{0x0017b2, "SK Telesys"}
{0x0017b3, "Aftek Infosys Limited"}
{0x0017b4, "Remote Security Systems"}
{0x0017b5, "Peerless Systems"}
{0x0017b6, "Aquantia"}
{0x0017b7, "Tonze Technology Co."}
{0x0017b8, "Novatron CO."}
{0x0017b9, "Gambro Lundia AB"}
{0x0017ba, "Sedo CO."}
{0x0017bb, "Syrinx Industrial Electronics"}
{0x0017bc, "Touchtunes Music"}
{0x0017bd, "Tibetsystem"}
{0x0017be, "Tratec Telecom B.V."}
{0x0017bf, "Coherent Research Limited"}
{0x0017c0, "PureTech Systems"}
{0x0017c1, "CM Precision Technology"}
{0x0017c2, "ADB Broadband Italia"}
{0x0017c3, "KTF Technologies"}
{0x0017c4, "Quanta Microsystems"}
{0x0017c5, "SonicWALL"}
{0x0017c6, "Cross Match Technologies"}
{0x0017c7, "Mara Systems Consulting AB"}
{0x0017c8, "Kyocera Mita"}
{0x0017c9, "Samsung Electronics Co."}
{0x0017ca, "Qisda"}
{0x0017cb, "Juniper Networks"}
{0x0017cc, "Alcatel-Lucent"}
{0x0017cd, "CEC Wireless R&D"}
{0x0017ce, "MB International Telecom Labs srl"}
{0x0017cf, "iMCA-GmbH"}
{0x0017d0, "Opticom Communications"}
{0x0017d1, "Nortel"}
{0x0017d2, "Thinlinx"}
{0x0017d3, "Etymotic Research"}
{0x0017d4, "Monsoon Multimedia"}
{0x0017d5, "Samsung Electronics Co."}
{0x0017d6, "Bluechips Microhouse Co."}
{0x0017d7, "ION Geophysical"}
{0x0017d8, "Magnum Semiconductor"}
{0x0017d9, "AAI"}
{0x0017da, "Spans Logic"}
{0x0017db, "Canko Technologies"}
{0x0017dc, "Daemyung Zero1"}
{0x0017dd, "Clipsal Australia"}
{0x0017de, "Advantage Six"}
{0x0017df, "Cisco Systems"}
{0x0017e0, "Cisco Systems"}
{0x0017e1, "Dacos Technologies Co."}
{0x0017e2, "Motorola Mobility"}
{0x0017e3, "Texas Instruments"}
{0x0017e4, "Texas Instruments"}
{0x0017e5, "Texas Instruments"}
{0x0017e6, "Texas Instruments"}
{0x0017e7, "Texas Instruments"}
{0x0017e8, "Texas Instruments"}
{0x0017e9, "Texas Instruments"}
{0x0017ea, "Texas Instruments"}
{0x0017eb, "Texas Instruments"}
{0x0017ec, "Texas Instruments"}
{0x0017ed, "WooJooIT"}
{0x0017ee, "Motorola Mobility"}
{0x0017ef, "IBM"}
{0x0017f0, "Szcom Broadband Network Technology Co."}
{0x0017f1, "Renu Electronics Pvt"}
{0x0017f2, "Apple Computer"}
{0x0017f3, "Harris Corparation"}
{0x0017f4, "Zeron Alliance"}
{0x0017f5, "LIG Neoptek"}
{0x0017f6, "Pyramid Meriden"}
{0x0017f7, "CEM Solutions Pvt"}
{0x0017f8, "Motech Industries"}
{0x0017f9, "Forcom Sp. z o.o."}
{0x0017fa, "Microsoft"}
{0x0017fb, "FA"}
{0x0017fc, "Suprema"}
{0x0017fd, "Amulet Hotkey"}
{0x0017fe, "Talos System"}
{0x0017ff, "Playline Co."}
{0x001800, "Unigrand"}
{0x001801, "Actiontec Electronics"}
{0x001802, "Alpha Networks"}
{0x001803, "ArcSoft Shanghai Co."}
{0x001804, "E-tek Digital Technology Limited"}
{0x001805, "Beijing InHand Networking Technology Co."}
{0x001806, "Hokkei Industries Co."}
{0x001807, "Fanstel"}
{0x001808, "SightLogix"}
{0x001809, "Cresyn"}
{0x00180a, "Meraki"}
{0x00180b, "Brilliant Telecommunications"}
{0x00180c, "Optelian Access Networks"}
{0x00180d, "Terabytes Server Storage Tech"}
{0x00180e, "Avega Systems"}
{0x00180f, "Nokia Danmark A/S"}
{0x001810, "IPTrade S.A."}
{0x001811, "Neuros Technology International"}
{0x001812, "Beijing Xinwei Telecom Technology Co."}
{0x001813, "Sony Ericsson Mobile Communications"}
{0x001814, "Mitutoyo"}
{0x001815, "GZ Technologies"}
{0x001816, "Ubixon Co."}
{0x001817, "D. E. Shaw Research"}
{0x001818, "Cisco Systems"}
{0x001819, "Cisco Systems"}
{0x00181a, "AVerMedia Information"}
{0x00181b, "TaiJin Metal Co."}
{0x00181c, "Exterity Limited"}
{0x00181d, "Asia Electronics Co."}
{0x00181e, "GDX Technologies"}
{0x00181f, "Palmmicro Communications"}
{0x001820, "w5networks"}
{0x001821, "Sindoricoh"}
{0x001822, "CEC Telecom Co."}
{0x001823, "Delta Electronics"}
{0x001824, "Kimaldi Electronics"}
{0x001825, "Private"}
{0x001826, "Cale Access AB"}
{0x001827, "NEC Unified Solutions Nederland B.V."}
{0x001828, "e2v technologies (UK)"}
{0x001829, "Gatsometer"}
{0x00182a, "Taiwan Video & Monitor"}
{0x00182b, "Softier"}
{0x00182c, "Ascend Networks"}
{0x00182d, "Artec Group O"}
{0x00182e, "XStreamHD"}
{0x00182f, "Texas Instruments"}
{0x001830, "Texas Instruments"}
{0x001831, "Texas Instruments"}
{0x001832, "Texas Instruments"}
{0x001833, "Texas Instruments"}
{0x001834, "Texas Instruments"}
{0x001835, "Thoratec / ITC"}
{0x001836, "Reliance Electric Limited"}
{0x001837, "Universal Abit Co."}
{0x001838, "PanAccess Communications"}
{0x001839, "Cisco-Linksys"}
{0x00183a, "Westell Technologies"}
{0x00183b, "Cenits Co."}
{0x00183c, "Encore Software Limited"}
{0x00183d, "Vertex Link"}
{0x00183e, "Digilent"}
{0x00183f, "2Wire"}
{0x001840, "3 Phoenix"}
{0x001841, "High Tech Computer"}
{0x001842, "Nokia Danmark A/S"}
{0x001843, "Dawevision"}
{0x001844, "Heads Up Technologies"}
{0x001845, "NPL Pulsar"}
{0x001846, "Crypto S.A."}
{0x001847, "AceNet Technology"}
{0x001848, "Vecima Networks"}
{0x001849, "Pigeon Point Systems"}
{0x00184a, "Catcher"}
{0x00184b, "Las Vegas Gaming"}
{0x00184c, "Bogen Communications"}
{0x00184d, "Netgear"}
{0x00184e, "Lianhe Technologies"}
{0x00184f, "8 Ways Technology"}
{0x001850, "Secfone Kft"}
{0x001851, "SWsoft"}
{0x001852, "StorLink Semiconductors"}
{0x001853, "Atera Networks"}
{0x001854, "Argard Co."}
{0x001855, "Aeromaritime Systembau GmbH"}
{0x001856, "EyeFi"}
{0x001857, "Unilever R&D"}
{0x001858, "TagMaster AB"}
{0x001859, "Strawberry Linux Co."}
{0x00185a, "uControl"}
{0x00185b, "Network Chemistry"}
{0x00185c, "EDS Lab Pte"}
{0x00185d, "Taiguen Technology (shen-zhen) CO."}
{0x00185e, "Nexterm"}
{0x00185f, "TAC"}
{0x001860, "SIM Technology Group Shanghai Simcom,"}
{0x001861, "Ooma"}
{0x001862, "Seagate Technology"}
{0x001863, "Veritech Electronics Limited"}
{0x001864, "Cybectec"}
{0x001865, "Siemens Healthcare Diagnostics Manufacturing"}
{0x001866, "Leutron Vision"}
{0x001867, "Evolution Robotics Retail"}
{0x001868, "Scientific Atlanta, A Cisco Company"}
{0x001869, "Kingjim"}
{0x00186a, "Global Link Digital Technology Co"}
{0x00186b, "Sambu Communics CO."}
{0x00186c, "Neonode AB"}
{0x00186d, "Zhenjiang Sapphire Electronic Industry CO."}
{0x00186e, "3Com"}
{0x00186f, "Setha Industria Eletronica Ltda"}
{0x001870, "E28 Shanghai Limited"}
{0x001871, "Hewlett-Packard Company"}
{0x001872, "Expertise Engineering"}
{0x001873, "Cisco Systems"}
{0x001874, "Cisco Systems"}
{0x001875, "AnaCise Testnology Pte"}
{0x001876, "WowWee"}
{0x001877, "Amplex A/S"}
{0x001878, "Mackware GmbH"}
{0x001879, "dSys"}
{0x00187a, "Wiremold"}
{0x00187b, "4NSYS Co."}
{0x00187c, "Intercross"}
{0x00187d, "Armorlink shanghai Co."}
{0x00187e, "RGB Spectrum"}
{0x00187f, "Zodianet"}
{0x001880, "Maxim Integrated Products"}
{0x001881, "Buyang Electronics Industrial Co."}
{0x001882, "Huawei Technologies Co."}
{0x001883, "Formosa21"}
{0x001884, "Fon Technology S.L."}
{0x001885, "Avigilon"}
{0x001886, "El-tech"}
{0x001887, "Metasystem SpA"}
{0x001888, "Gotive a.s."}
{0x001889, "WinNet Solutions Limited"}
{0x00188a, "Infinova"}
{0x00188b, "Dell"}
{0x00188c, "Mobile Action Technology"}
{0x00188d, "Nokia Danmark A/S"}
{0x00188e, "Ekahau"}
{0x00188f, "Montgomery Technology"}
{0x001890, "RadioCOM, s.r.o."}
{0x001891, "Zhongshan General K-mate Electronics Co."}
{0x001892, "ads-tec GmbH"}
{0x001893, "Shenzhen Photon Broadband Technology Co."}
{0x001894, "zimocom"}
{0x001895, "Hansun Technologies"}
{0x001896, "Great Well Electronic"}
{0x001897, "Jess-link Products Co."}
{0x001898, "Kingstate Electronics"}
{0x001899, "ShenZhen jieshun Science&Technology Industry CO"}
{0x00189a, "Hana Micron"}
{0x00189b, "Thomson"}
{0x00189c, "Weldex"}
{0x00189d, "Navcast"}
{0x00189e, "Omnikey GmbH."}
{0x00189f, "Lenntek"}
{0x0018a0, "Cierma Ascenseurs"}
{0x0018a1, "Tiqit Computers"}
{0x0018a2, "XIP Technology AB"}
{0x0018a3, "Zippy Technology"}
{0x0018a4, "Motorola Mobility"}
{0x0018a5, "ADigit Technologies"}
{0x0018a6, "Persistent Systems"}
{0x0018a7, "Yoggie Security Systems"}
{0x0018a8, "AnNeal Technology"}
{0x0018a9, "Ethernet Direct"}
{0x0018aa, "Protec Fire Detection plc"}
{0x0018ab, "Beijing Lhwt Microelectronics"}
{0x0018ac, "Shanghai Jiao Da Hisys Technology Co."}
{0x0018ad, "Nidec Sankyo"}
{0x0018ae, "TVT Co."}
{0x0018af, "Samsung Electronics Co."}
{0x0018b0, "Nortel"}
{0x0018b1, "IBM"}
{0x0018b2, "Adeunis RF"}
{0x0018b3, "TEC WizHome Co."}
{0x0018b4, "Dawon Media"}
{0x0018b5, "Magna Carta"}
{0x0018b6, "S3C"}
{0x0018b7, "D3 LED"}
{0x0018b8, "New Voice International AG"}
{0x0018b9, "Cisco Systems"}
{0x0018ba, "Cisco Systems"}
{0x0018bb, "Eliwell Controls srl"}
{0x0018bc, "ZAO NVP Bolid"}
{0x0018bd, "Shenzhen Dvbworld Technology CO."}
{0x0018be, "Ansa"}
{0x0018bf, "Essence Technology Solution"}
{0x0018c0, "Motorola Mobility"}
{0x0018c1, "Almitec Informtica e Comrcio Ltda."}
{0x0018c2, "Firetide"}
{0x0018c3, "CS"}
{0x0018c4, "Raba Technologies"}
{0x0018c5, "Nokia Danmark A/S"}
{0x0018c6, "OPW Fuel Management Systems"}
{0x0018c7, "Real Time Automation"}
{0x0018c8, "Isonas"}
{0x0018c9, "EOps Technology Limited"}
{0x0018ca, "Viprinet GmbH"}
{0x0018cb, "Tecobest Technology Limited"}
{0x0018cc, "Axiohm SAS"}
{0x0018cd, "Erae Electronics Industry Co."}
{0x0018ce, "Dreamtech Co."}
{0x0018cf, "Baldor Electric Company"}
{0x0018d0, "AtRoad,  A Trimble Company"}
{0x0018d1, "Siemens Home & Office Comm. Devices"}
{0x0018d2, "High-Gain Antennas"}
{0x0018d3, "Teamcast"}
{0x0018d4, "Unified Display Interface SIG"}
{0x0018d5, "Reigncom"}
{0x0018d6, "Swirlnet A/S"}
{0x0018d7, "Javad Navigation Systems"}
{0x0018d8, "Arch Meter"}
{0x0018d9, "Santosha Internatonal"}
{0x0018da, "Amber Wireless Gmbh"}
{0x0018db, "EPL Technology"}
{0x0018dc, "Prostar Co."}
{0x0018dd, "Silicondust Engineering"}
{0x0018de, "Intel"}
{0x0018df, "The Morey"}
{0x0018e0, "Anaveo"}
{0x0018e1, "Verkerk Service Systemen"}
{0x0018e2, "Topdata Sistemas de Automacao Ltda"}
{0x0018e3, "Visualgate Systems"}
{0x0018e4, "Yiguang"}
{0x0018e5, "Adhoco AG"}
{0x0018e6, "Computer Hardware Design SIA"}
{0x0018e7, "Cameo Communications"}
{0x0018e8, "Hacetron"}
{0x0018e9, "Numata"}
{0x0018ea, "Alltec GmbH"}
{0x0018eb, "BroVis Wireless Networks"}
{0x0018ec, "Welding Technology"}
{0x0018ed, "Accutech Ultrasystems Co."}
{0x0018ee, "Videology Imaging Solutions"}
{0x0018ef, "Escape Communications"}
{0x0018f0, "Joytoto Co."}
{0x0018f1, "Chunichi Denshi Co."}
{0x0018f2, "Beijing Tianyu Communication Equipment Co."}
{0x0018f3, "Asustek Computer"}
{0x0018f4, "EO Technics Co."}
{0x0018f5, "Shenzhen Streaming Video Technology Company Limited"}
{0x0018f6, "Thomson Telecom Belgium"}
{0x0018f7, "Kameleon Technologies"}
{0x0018f8, "Cisco-Linksys"}
{0x0018f9, "Vvond"}
{0x0018fa, "Yushin Precision Equipment Co."}
{0x0018fb, "Compro Technology"}
{0x0018fc, "Altec Electronic AG"}
{0x0018fd, "Optimal Technologies International"}
{0x0018fe, "Hewlett-Packard Company"}
{0x0018ff, "PowerQuattro Co."}
{0x001900, "Intelliverese - DBA Voicecom"}
{0x001901, "F1media"}
{0x001902, "Cambridge Consultants"}
{0x001903, "Bigfoot Networks"}
{0x001904, "WB Electronics Sp. z o.o."}
{0x001905, "Schrack Seconet AG"}
{0x001906, "Cisco Systems"}
{0x001907, "Cisco Systems"}
{0x001908, "Duaxes"}
{0x001909, "Devi A/S"}
{0x00190a, "Hasware"}
{0x00190b, "Southern Vision Systems"}
{0x00190c, "Encore Electronics"}
{0x00190d, "Ieee 1394c"}
{0x00190e, "Atech Technology Co."}
{0x00190f, "Advansus"}
{0x001910, "Knick Elektronische Messgeraete GmbH & Co. KG"}
{0x001911, "Just In Mobile Information Technologies (Shanghai) Co."}
{0x001912, "Welcat"}
{0x001913, "Chuang-Yi Network EquipmentLtd."}
{0x001914, "Winix Co."}
{0x001915, "Tecom Co."}
{0x001916, "PayTec AG"}
{0x001917, "Posiflex"}
{0x001918, "Interactive Wear AG"}
{0x001919, "Astel"}
{0x00191a, "Irlink"}
{0x00191b, "Sputnik Engineering AG"}
{0x00191c, "Sensicast Systems"}
{0x00191d, "Nintendo Co."}
{0x00191e, "Beyondwiz Co."}
{0x00191f, "Microlink communications"}
{0x001920, "Kume Electric Co."}
{0x001921, "Elitegroup Computer System Co."}
{0x001922, "CM Comandos Lineares"}
{0x001923, "Phonex Korea Co."}
{0x001924, "Lbnl  Engineering"}
{0x001925, "Intelicis"}
{0x001926, "BitsGen Co."}
{0x001927, "ImCoSys"}
{0x001928, "Siemens AG, Transportation Systems"}
{0x001929, "2m2b Montadora de Maquinas Bahia Brasil Ltda"}
{0x00192a, "Antiope Associates"}
{0x00192b, "Aclara RF Systems"}
{0x00192c, "Motorola Mobility"}
{0x00192d, "Nokia"}
{0x00192e, "Spectral Instruments"}
{0x00192f, "Cisco Systems"}
{0x001930, "Cisco Systems"}
{0x001931, "Balluff GmbH"}
{0x001932, "Gude Analog- und Digialsysteme GmbH"}
{0x001933, "Strix Systems"}
{0x001934, "Trendon Touch Technology"}
{0x001935, "Duerr Dental GmbH & Co. KG"}
{0x001936, "Sterlite Optical Technologies Limited"}
{0x001937, "CommerceGuard AB"}
{0x001938, "UMB Communications Co."}
{0x001939, "Gigamips"}
{0x00193a, "Oesolutions"}
{0x00193b, "Wilibox Deliberant Group"}
{0x00193c, "HighPoint Technologies Incorporated"}
{0x00193d, "GMC Guardian Mobility"}
{0x00193e, "ADB Broadband Italia"}
{0x00193f, "RDI technology(Shenzhen) Co."}
{0x001940, "Rackable Systems"}
{0x001941, "Pitney Bowes"}
{0x001942, "ON Software International Limited"}
{0x001943, "Belden"}
{0x001944, "Fossil Partners"}
{0x001945, "Ten-Tec"}
{0x001946, "Cianet Industria e Comercio S/A"}
{0x001947, "Scientific Atlanta, A Cisco Company"}
{0x001948, "AireSpider Networks"}
{0x001949, "Tentel  Comtech CO."}
{0x00194a, "Testo AG"}
{0x00194b, "Sagem Communication"}
{0x00194c, "Fujian Stelcom information & Technology CO."}
{0x00194d, "Avago Technologies Sdn Bhd"}
{0x00194e, "Ultra Electronics - TCS (Tactical Communication Systems)"}
{0x00194f, "Nokia Danmark A/S"}
{0x001950, "Harman Multimedia"}
{0x001951, "Netcons, S.r.o."}
{0x001952, "Acogito Co."}
{0x001953, "Chainleader Communications"}
{0x001954, "Leaf"}
{0x001955, "Cisco Systems"}
{0x001956, "Cisco Systems"}
{0x001957, "Saafnet Canada"}
{0x001958, "Bluetooth SIG"}
{0x001959, "Staccato Communications"}
{0x00195a, "Jenaer Antriebstechnik GmbH"}
{0x00195b, "D-Link"}
{0x00195c, "Innotech"}
{0x00195d, "ShenZhen XinHuaTong Opto Electronics Co."}
{0x00195e, "Motorola Mobility"}
{0x00195f, "Valemount Networks"}
{0x001960, "DoCoMo Systems"}
{0x001961, "Blaupunkt GmbH"}
{0x001962, "Commerciant"}
{0x001963, "Sony Ericsson Mobile Communications AB"}
{0x001964, "Doorking"}
{0x001965, "YuHua TelTech (ShangHai) Co."}
{0x001966, "Asiarock Technology Limited"}
{0x001967, "Teldat Sp.J."}
{0x001968, "Digital Video Networks(Shanghai) CO."}
{0x001969, "Nortel"}
{0x00196a, "MikroM GmbH"}
{0x00196b, "Danpex"}
{0x00196c, "Etrovision Technology"}
{0x00196d, "Raybit Systems Korea"}
{0x00196e, "Metacom (Pty)"}
{0x00196f, "SensoPart GmbH"}
{0x001970, "Z-Com"}
{0x001971, "Guangzhou Unicomp Technology Co."}
{0x001972, "Plexus (Xiamen) Co."}
{0x001973, "Zeugma Systems"}
{0x001974, "AboCom Systems"}
{0x001975, "Beijing Huisen networks technology"}
{0x001976, "Xipher Technologies"}
{0x001977, "Aerohive Networks"}
{0x001978, "Datum Systems"}
{0x001979, "Nokia Danmark A/S"}
{0x00197a, "MAZeT GmbH"}
{0x00197b, "Picotest"}
{0x00197c, "Riedel Communications GmbH"}
{0x00197d, "Hon Hai Precision Ind. Co."}
{0x00197e, "Hon Hai Precision Ind. Co."}
{0x00197f, "Plantronics"}
{0x001980, "Gridpoint Systems"}
{0x001981, "Vivox"}
{0x001982, "SmarDTV"}
{0x001983, "CCT R&D Limited"}
{0x001984, "Estic"}
{0x001985, "IT Watchdogs"}
{0x001986, "Cheng Hongjian"}
{0x001987, "Panasonic Mobile Communications Co."}
{0x001988, "Wi2Wi"}
{0x001989, "Sonitrol"}
{0x00198a, "Northrop Grumman Systems"}
{0x00198b, "Novera Optics Korea"}
{0x00198c, "iXSea"}
{0x00198d, "Ocean Optics"}
{0x00198e, "Oticon A/S"}
{0x00198f, "Alcatel Bell N.V."}
{0x001990, "ELM Data Co."}
{0x001991, "avinfo"}
{0x001992, "Adtran"}
{0x001993, "Changshu Switchgear MFG. Co.,Ltd. (Former Changshu Switchgea"}
{0x001994, "Jorjin Technologies"}
{0x001995, "Jurong Hi-Tech (Suzhou)Co.ltd"}
{0x001996, "TurboChef Technologies"}
{0x001997, "Soft Device Sdn Bhd"}
{0x001998, "Sato"}
{0x001999, "Fujitsu Technology Solutions"}
{0x00199a, "Edo-evi"}
{0x00199b, "Diversified Technical Systems"}
{0x00199c, "Ctring"}
{0x00199d, "Vizio"}
{0x00199e, "Showadenshi Electronics"}
{0x00199f, "DKT A/S"}
{0x0019a0, "Nihon Data Systens"}
{0x0019a1, "LG Information & COMM."}
{0x0019a2, "Ordyn Technologies"}
{0x0019a3, "asteel electronique atlantique"}
{0x0019a4, "Austar Technology (hang zhou) Co."}
{0x0019a5, "RadarFind"}
{0x0019a6, "Motorola Mobility"}
{0x0019a7, "Itu-t"}
{0x0019a8, "WiQuest Communications"}
{0x0019a9, "Cisco Systems"}
{0x0019aa, "Cisco Systems"}
{0x0019ab, "Raycom CO"}
{0x0019ac, "GSP Systems"}
{0x0019ad, "Bobst SA"}
{0x0019ae, "Hopling Technologies b.v."}
{0x0019af, "Rigol Technologies"}
{0x0019b0, "HanYang System"}
{0x0019b1, "Arrow7"}
{0x0019b2, "XYnetsoft Co."}
{0x0019b3, "Stanford Research Systems"}
{0x0019b4, "VideoCast"}
{0x0019b5, "Famar Fueguina S.A."}
{0x0019b6, "Euro Emme s.r.l."}
{0x0019b7, "Nokia Danmark A/S"}
{0x0019b8, "Boundary Devices"}
{0x0019b9, "Dell"}
{0x0019ba, "Paradox Security Systems"}
{0x0019bb, "Hewlett-Packard Company"}
{0x0019bc, "Electro Chance SRL"}
{0x0019bd, "New Media Life"}
{0x0019be, "Altai Technologies Limited"}
{0x0019bf, "Citiway technology Co."}
{0x0019c0, "Motorola Mobility"}
{0x0019c1, "Alps Electric Co."}
{0x0019c2, "Equustek Solutions"}
{0x0019c3, "Qualitrol"}
{0x0019c4, "Infocrypt"}
{0x0019c5, "Sony Computer Entertainment,"}
{0x0019c6, "ZTE"}
{0x0019c7, "Cambridge Industries(Group) Co."}
{0x0019c8, "AnyDATA"}
{0x0019c9, "S&C Electric Company"}
{0x0019ca, "Broadata Communications"}
{0x0019cb, "ZyXEL Communications"}
{0x0019cc, "RCG (HK)"}
{0x0019cd, "Chengdu ethercom information technology"}
{0x0019ce, "Progressive Gaming International"}
{0x0019cf, "Salicru"}
{0x0019d0, "Cathexis"}
{0x0019d1, "Intel"}
{0x0019d2, "Intel"}
{0x0019d3, "Trak Microwave"}
{0x0019d4, "ICX Technologies"}
{0x0019d5, "IP Innovations"}
{0x0019d6, "LS Cable"}
{0x0019d7, "Fortunetek CO."}
{0x0019d8, "Maxfor"}
{0x0019d9, "Zeutschel GmbH"}
{0x0019da, "Welltrans O&E Technology Co. "}
{0x0019db, "Micro-star International CO."}
{0x0019dc, "Enensys Technologies"}
{0x0019dd, "FEI-Zyfer"}
{0x0019de, "Mobitek"}
{0x0019df, "Thomson"}
{0x0019e0, "Tp-link Technologies Co."}
{0x0019e1, "Nortel"}
{0x0019e2, "Juniper Networks"}
{0x0019e3, "Apple Computer"}
{0x0019e4, "2Wire"}
{0x0019e5, "Lynx Studio Technology"}
{0x0019e6, "Toyo Medic Co."}
{0x0019e7, "Cisco Systems"}
{0x0019e8, "Cisco Systems"}
{0x0019e9, "S-Information Technolgy, Co."}
{0x0019ea, "TeraMage Technologies Co."}
{0x0019eb, "Pyronix"}
{0x0019ec, "Sagamore Systems"}
{0x0019ed, "Axesstel"}
{0x0019ee, "Carlo Gavazzi Controls Spa-controls Division"}
{0x0019ef, "Shenzhen Linnking Electronics Co."}
{0x0019f0, "Unionman Technology Co."}
{0x0019f1, "Star Communication Network Technology Co."}
{0x0019f2, "Teradyne K.K."}
{0x0019f3, "Cetis"}
{0x0019f4, "Convergens Oy"}
{0x0019f5, "Imagination Technologies"}
{0x0019f6, "Acconet (PTE)"}
{0x0019f7, "Onset Computer"}
{0x0019f8, "Embedded Systems Design"}
{0x0019f9, "TDK-Lambda"}
{0x0019fa, "Cable Vision Electronics CO."}
{0x0019fb, "BSkyB"}
{0x0019fc, "PT. Ufoakses Sukses Luarbiasa"}
{0x0019fd, "Nintendo Co."}
{0x0019fe, "Shenzhen Seecomm Technology Co."}
{0x0019ff, "Finnzymes"}
{0x001a00, "Matrix"}
{0x001a01, "Smiths Medical"}
{0x001a02, "Secure Care Products"}
{0x001a03, "Angel Electronics Co."}
{0x001a04, "Interay Solutions BV"}
{0x001a05, "Optibase"}
{0x001a06, "OpVista"}
{0x001a07, "Arecont Vision"}
{0x001a08, "Dalman Technical Services"}
{0x001a09, "Wayfarer Transit Systems"}
{0x001a0a, "Adaptive Micro-Ware"}
{0x001a0b, "Bona Technology"}
{0x001a0c, "Swe-Dish Satellite Systems AB"}
{0x001a0d, "HandHeld entertainment"}
{0x001a0e, "Cheng Uei Precision Industry Co."}
{0x001a0f, "Sistemas Avanzados de Control"}
{0x001a10, "Lucent Trans Electronics Co."}
{0x001a11, "Google"}
{0x001a12, "Essilor"}
{0x001a13, "Wanlida Group Co."}
{0x001a14, "Xin Hua Control Engineering Co."}
{0x001a15, "gemalto e-Payment"}
{0x001a16, "Nokia Danmark A/S"}
{0x001a17, "Teak Technologies"}
{0x001a18, "Advanced Simulation Technology"}
{0x001a19, "Computer Engineering Limited"}
{0x001a1a, "Gentex/Electro-Acoustic Products"}
{0x001a1b, "Motorola Mobility"}
{0x001a1c, "GT&T Engineering Pte"}
{0x001a1d, "PChome Online"}
{0x001a1e, "Aruba Networks"}
{0x001a1f, "Coastal Environmental Systems"}
{0x001a20, "Cmotech Co."}
{0x001a21, "Indac B.V."}
{0x001a22, "eQ-3 Entwicklung GmbH"}
{0x001a23, "Ice Qube"}
{0x001a24, "Galaxy Telecom Technologies"}
{0x001a25, "Delta Dore"}
{0x001a26, "Deltanode Solutions AB"}
{0x001a27, "Ubistar"}
{0x001a28, "Aswt Co., Taiwan Branch H.K."}
{0x001a29, "Techsonic Industries d/b/a Humminbird"}
{0x001a2a, "Arcadyan Technology"}
{0x001a2b, "Ayecom Technology Co."}
{0x001a2c, "Satec Co."}
{0x001a2d, "The Navvo Group"}
{0x001a2e, "Ziova Coporation"}
{0x001a2f, "Cisco Systems"}
{0x001a30, "Cisco Systems"}
{0x001a31, "Scan Coin Industries AB"}
{0x001a32, "Activa Multimedia"}
{0x001a33, "ASI Communications"}
{0x001a34, "Konka Group Co."}
{0x001a35, "Bartec Gmbh"}
{0x001a36, "Aipermon GmbH & Co. KG"}
{0x001a37, "Lear"}
{0x001a38, "Sanmina-SCI"}
{0x001a39, "Merten GmbH&CoKG"}
{0x001a3a, "Dongahelecomm"}
{0x001a3b, "Doah Elecom"}
{0x001a3c, "Technowave"}
{0x001a3d, "Ajin Vision Co."}
{0x001a3e, "Faster Technology"}
{0x001a3f, "intelbras"}
{0x001a40, "A-four Tech CO."}
{0x001a41, "Inocova Co."}
{0x001a42, "Techcity Technology co."}
{0x001a43, "Logical Link Communications"}
{0x001a44, "JWTrading Co."}
{0x001a45, "GN Netcom as"}
{0x001a46, "Digital Multimedia Technology Co."}
{0x001a47, "Agami Systems"}
{0x001a48, "Takacom"}
{0x001a49, "Micro Vision Co."}
{0x001a4a, "Qumranet"}
{0x001a4b, "Hewlett-Packard Company"}
{0x001a4c, "Crossbow Technology"}
{0x001a4d, "Giga-byte Technology Co."}
{0x001a4e, "NTI AG / LinMot"}
{0x001a4f, "AVM GmbH"}
{0x001a50, "PheeNet Technology"}
{0x001a51, "Alfred Mann Foundation"}
{0x001a52, "Meshlinx Wireless"}
{0x001a53, "Zylaya"}
{0x001a54, "Hip Shing Electronics"}
{0x001a55, "ACA-Digital"}
{0x001a56, "ViewTel Co"}
{0x001a57, "Matrix Design Group"}
{0x001a58, "CCV Deutschland GmbH - Celectronic eHealth Div."}
{0x001a59, "Ircona"}
{0x001a5a, "Korea Electric Power Data Network  (KDN) Co."}
{0x001a5b, "NetCare Service Co."}
{0x001a5c, "Euchner GmbH+Co. KG"}
{0x001a5d, "Mobinnova"}
{0x001a5e, "Thincom Technology Co."}
{0x001a5f, "KitWorks.fi"}
{0x001a60, "Wave Electronics Co."}
{0x001a61, "PacStar"}
{0x001a62, "Data Robotics, Incorporated"}
{0x001a63, "Elster Solutions"}
{0x001a64, "IBM"}
{0x001a65, "Seluxit"}
{0x001a66, "Motorola Mobility"}
{0x001a67, "Infinite QL Sdn Bhd"}
{0x001a68, "Weltec Enterprise Co."}
{0x001a69, "Wuhan Yangtze Optical Technology CO."}
{0x001a6a, "Tranzas"}
{0x001a6b, "Universal Global Scientific Industrial Co."}
{0x001a6c, "Cisco Systems"}
{0x001a6d, "Cisco Systems"}
{0x001a6e, "Impro Technologies"}
{0x001a6f, "MI.TEL s.r.l."}
{0x001a70, "Cisco-Linksys"}
{0x001a71, "Diostech Co."}
{0x001a72, "Mosart Semiconductor"}
{0x001a73, "Gemtek Technology Co."}
{0x001a74, "Procare International Co"}
{0x001a75, "Sony Ericsson Mobile Communications"}
{0x001a76, "SDT information Technology Co."}
{0x001a77, "Motorola Mobility"}
{0x001a78, "ubtos"}
{0x001a79, "Telecomunication Technologies"}
{0x001a7a, "Lismore Instruments Limited"}
{0x001a7b, "Teleco"}
{0x001a7c, "Hirschmann Multimedia B.V."}
{0x001a7d, "cyber-blue(HK)Ltd"}
{0x001a7e, "LN Srithai Comm"}
{0x001a7f, "GCI Science&Technology Co."}
{0x001a80, "Sony"}
{0x001a81, "Zelax"}
{0x001a82, "Proba Building Automation Co."}
{0x001a83, "Pegasus Technologies"}
{0x001a84, "V One Multimedia Pte"}
{0x001a85, "NV Michel Van de Wiele"}
{0x001a86, "AdvancedIO Systems"}
{0x001a87, "Canhold International Limited"}
{0x001a88, "Venergy"}
{0x001a89, "Nokia Danmark A/S"}
{0x001a8a, "Samsung Electronics Co."}
{0x001a8b, "Chunil Electric IND."}
{0x001a8c, "Astaro AG"}
{0x001a8d, "Avecs Bergen Gmbh"}
{0x001a8e, "3Way Networks"}
{0x001a8f, "Nortel"}
{0x001a90, "Trpico Sistemas e Telecomunicaes da Amaznia LTDA."}
{0x001a91, "FusionDynamic"}
{0x001a92, "Asustek Computer"}
{0x001a93, "Erco Leuchten Gmbh"}
{0x001a94, "Votronic GmbH"}
{0x001a95, "Hisense Mobile Communications Technoligy Co."}
{0x001a96, "Ecler S.A."}
{0x001a97, "fitivision technology"}
{0x001a98, "Asotel Communication Limited Taiwan Branch"}
{0x001a99, "Smarty (HZ) Information Electronics Co."}
{0x001a9a, "Skyworth Digital technology(shenzhen)co.ltd."}
{0x001a9b, "Adec & Parter AG"}
{0x001a9c, "RightHand Technologies"}
{0x001a9d, "Skipper Wireless"}
{0x001a9e, "Icon Digital International Limited"}
{0x001a9f, "A-Link Europe"}
{0x001aa0, "Dell"}
{0x001aa1, "Cisco Systems"}
{0x001aa2, "Cisco Systems"}
{0x001aa3, "Delorme"}
{0x001aa4, "Future University-Hakodate"}
{0x001aa5, "BRN Phoenix"}
{0x001aa6, "Telefunken Radio Communication Systems GmbH &CO.KG"}
{0x001aa7, "Torian Wireless"}
{0x001aa8, "Mamiya Digital Imaging Co."}
{0x001aa9, "Fujian Star-net Communication Co."}
{0x001aaa, "Analogic"}
{0x001aab, "eWings s.r.l."}
{0x001aac, "Corelatus AB"}
{0x001aad, "Motorola Mobility"}
{0x001aae, "Savant Systems"}
{0x001aaf, "Blusens Technology"}
{0x001ab0, "Signal Networks Pvt.,"}
{0x001ab1, "Asia Pacific Satellite Industries Co."}
{0x001ab2, "Cyber Solutions"}
{0x001ab3, "Visionite"}
{0x001ab4, "Ffei"}
{0x001ab5, "Home Network System"}
{0x001ab6, "Texas Instruments"}
{0x001ab7, "Ethos Networks"}
{0x001ab8, "Anseri"}
{0x001ab9, "PMC"}
{0x001aba, "Caton Overseas Limited"}
{0x001abb, "Fontal Technology Incorporation"}
{0x001abc, "U4EA Technologies"}
{0x001abd, "Impatica"}
{0x001abe, "Computer Hi-tech"}
{0x001abf, "Trumpf Laser Marking Systems AG"}
{0x001ac0, "Joybien Technologies CO."}
{0x001ac1, "3Com"}
{0x001ac2, "YEC Co."}
{0x001ac3, "Scientific-Atlanta"}
{0x001ac4, "2Wire"}
{0x001ac5, "BreakingPoint Systems"}
{0x001ac6, "Micro Control Designs"}
{0x001ac7, "Unipoint"}
{0x001ac8, "ISL (Instrumentation Scientifique de Laboratoire)"}
{0x001ac9, "Suzuken Co."}
{0x001aca, "Tilera"}
{0x001acb, "Autocom Products"}
{0x001acc, "Celestial Semiconductor"}
{0x001acd, "Tidel Engineering LP"}
{0x001ace, "Yupiteru"}
{0x001acf, "C.T. Elettronica"}
{0x001ad0, "Albis Technologies AG"}
{0x001ad1, "Fargo CO."}
{0x001ad2, "Eletronica Nitron Ltda"}
{0x001ad3, "Vamp"}
{0x001ad4, "iPOX Technology Co."}
{0x001ad5, "KMC Chain Industrial CO."}
{0x001ad6, "Jiagnsu Aetna Electric Co."}
{0x001ad7, "Christie Digital Systems"}
{0x001ad8, "AlsterAero GmbH"}
{0x001ad9, "International Broadband Electric Communications"}
{0x001ada, "Biz-2-Me"}
{0x001adb, "Motorola Mobility"}
{0x001adc, "Nokia Danmark A/S"}
{0x001add, "PePWave"}
{0x001ade, "Motorola Mobility"}
{0x001adf, "Interactivetv Limited"}
{0x001ae0, "Mythology Tech Express"}
{0x001ae1, "Edge Access"}
{0x001ae2, "Cisco Systems"}
{0x001ae3, "Cisco Systems"}
{0x001ae4, "Medicis Technologies"}
{0x001ae5, "Mvox Technologies"}
{0x001ae6, "Atlanta Advanced Communications Holdings Limited"}
{0x001ae7, "Aztek Networks"}
{0x001ae8, "Siemens Enterprise Communications GmbH & Co. KG"}
{0x001ae9, "Nintendo Co."}
{0x001aea, "Radio Terminal Systems"}
{0x001aeb, "Allied Telesis K.K."}
{0x001aec, "Keumbee Electronics Co."}
{0x001aed, "Incotec Gmbh"}
{0x001aee, "Shenztech"}
{0x001aef, "Loopcomm Technology"}
{0x001af0, "Alcatel - IPD"}
{0x001af1, "Embedded Artists AB"}
{0x001af2, "Dynavisions Schweiz AG"}
{0x001af3, "Samyoung Electronics"}
{0x001af4, "Handreamnet"}
{0x001af5, "Pentaone. CO."}
{0x001af6, "Woven Systems"}
{0x001af7, "dataschalt e+a GmbH"}
{0x001af8, "Copley Controls"}
{0x001af9, "AeroVIronment (AV)"}
{0x001afa, "Welch Allyn"}
{0x001afb, "Joby"}
{0x001afc, "ModusLink"}
{0x001afd, "Evolis"}
{0x001afe, "Sofacreal"}
{0x001aff, "Wizyoung Tech."}
{0x001b00, "Neopost Technologies"}
{0x001b01, "Applied Radio Technologies"}
{0x001b02, "EDLtd"}
{0x001b03, "Action Technology (SZ) Co."}
{0x001b04, "Affinity International S.p.a"}
{0x001b05, "YMC AG"}
{0x001b06, "Ateliers R. Laumonier"}
{0x001b07, "Mendocino Software"}
{0x001b08, "Danfoss Drives A/S"}
{0x001b09, "Matrix Telecom Pvt."}
{0x001b0a, "Intelligent Distributed Controls"}
{0x001b0b, "Phidgets"}
{0x001b0c, "Cisco Systems"}
{0x001b0d, "Cisco Systems"}
{0x001b0e, "InoTec GmbH Organisationssysteme"}
{0x001b0f, "Petratec"}
{0x001b10, "ShenZhen Kang Hui Technology Co."}
{0x001b11, "D-Link"}
{0x001b12, "Apprion"}
{0x001b13, "Icron Technologies"}
{0x001b14, "Carex Lighting Equipment Factory"}
{0x001b15, "Voxtel"}
{0x001b16, "Celtro"}
{0x001b17, "Palo Alto Networks"}
{0x001b18, "Tsuken Electric Ind. Co."}
{0x001b19, "Ieee I&M Society TC9"}
{0x001b1a, "e-trees Japan"}
{0x001b1b, "Siemens AG,"}
{0x001b1c, "Coherent"}
{0x001b1d, "Phoenix International Co."}
{0x001b1e, "Hart Communication Foundation"}
{0x001b1f, "Delta - Danish Electronics, Light & Acoustics"}
{0x001b20, "TPine Technology"}
{0x001b21, "Intel Corporate"}
{0x001b22, "Palit Microsystems ( H.K.)"}
{0x001b23, "SimpleComTools"}
{0x001b24, "Quanta Computer"}
{0x001b25, "Nortel"}
{0x001b26, "RON-Telecom ZAO"}
{0x001b27, "Merlin CSI"}
{0x001b28, "Polygon"}
{0x001b29, "Avantis.Co."}
{0x001b2a, "Cisco Systems"}
{0x001b2b, "Cisco Systems"}
{0x001b2c, "Atron Electronic Gmbh"}
{0x001b2d, "Med-Eng Systems"}
{0x001b2e, "Sinkyo Electron"}
{0x001b2f, "Netgear"}
{0x001b30, "Solitech"}
{0x001b31, "Neural Image. Co."}
{0x001b32, "QLogic"}
{0x001b33, "Nokia Danmark A/S"}
{0x001b34, "Focus System"}
{0x001b35, "Chongqing Jinou Science & Technology Development Co."}
{0x001b36, "Tsubata Engineering Co.,Ltd. (Head Office)"}
{0x001b37, "Computec Oy"}
{0x001b38, "Compal Information (kunshan) CO."}
{0x001b39, "Proxicast"}
{0x001b3a, "Sims"}
{0x001b3b, "Yi-Qing CO."}
{0x001b3c, "Software Technologies Group"}
{0x001b3d, "EuroTel Spa"}
{0x001b3e, "Curtis"}
{0x001b3f, "ProCurve Networking by HP"}
{0x001b40, "Network Automation mxc AB"}
{0x001b41, "General Infinity Co."}
{0x001b42, "Wise & Blue"}
{0x001b43, "Beijing DG Telecommunications equipment Co."}
{0x001b44, "SanDisk"}
{0x001b45, "ABB AS, Division Automation Products"}
{0x001b46, "Blueone Technology Co."}
{0x001b47, "Futarque A/S"}
{0x001b48, "Shenzhen Lantech Electronics Co."}
{0x001b49, "Roberts Radio limited"}
{0x001b4a, "W&W Communications"}
{0x001b4b, "Sanion Co."}
{0x001b4c, "Signtech"}
{0x001b4d, "Areca Technology"}
{0x001b4e, "Navman New Zealand"}
{0x001b4f, "Avaya"}
{0x001b50, "Nizhny Novgorod Factory Named After M.frunze, Fsue (nzif)"}
{0x001b51, "Vector Technology"}
{0x001b52, "Motorola Mobility"}
{0x001b53, "Cisco Systems"}
{0x001b54, "Cisco Systems"}
{0x001b55, "Hurco Automation"}
{0x001b56, "Tehuti Networks"}
{0x001b57, "Semindia Systems Private Limited"}
{0x001b58, "ACE CAD Enterprise Co."}
{0x001b59, "Sony Ericsson Mobile Communications AB"}
{0x001b5a, "Apollo Imaging Technologies"}
{0x001b5b, "2Wire"}
{0x001b5c, "Azuretec Co."}
{0x001b5d, "Vololink"}
{0x001b5e, "BPL Limited"}
{0x001b5f, "Alien Technology"}
{0x001b60, "Navigon AG"}
{0x001b61, "Digital Acoustics"}
{0x001b62, "JHT Optoelectronics Co."}
{0x001b63, "Apple Computer"}
{0x001b64, "IsaacLandKorea Co."}
{0x001b65, "China Gridcom Co."}
{0x001b66, "Sennheiser electronic GmbH & Co. KG"}
{0x001b67, "Ubiquisys"}
{0x001b68, "Modnnet Co."}
{0x001b69, "Equaline"}
{0x001b6a, "Powerwave Technologies Sweden AB"}
{0x001b6b, "Swyx Solutions AG"}
{0x001b6c, "LookX Digital Media BV"}
{0x001b6d, "Midtronics"}
{0x001b6e, "Anue Systems"}
{0x001b6f, "Teletrak"}
{0x001b70, "IRI Ubiteq"}
{0x001b71, "Telular"}
{0x001b72, "Sicep s.p.a."}
{0x001b73, "DTL Broadcast"}
{0x001b74, "MiraLink"}
{0x001b75, "Hypermedia Systems"}
{0x001b76, "Ripcode"}
{0x001b77, "Intel Corporate"}
{0x001b78, "Hewlett-Packard Company"}
{0x001b79, "Faiveley Transport"}
{0x001b7a, "Nintendo Co."}
{0x001b7b, "The Tintometer"}
{0x001b7c, "A & R Cambridge"}
{0x001b7d, "CXR Anderson Jacobson"}
{0x001b7e, "Beckmann GmbH"}
{0x001b7f, "TMN Technologies Telecomunicacoes Ltda"}
{0x001b80, "Lord"}
{0x001b81, "Dataq Instruments"}
{0x001b82, "Taiwan Semiconductor Co."}
{0x001b83, "Finsoft"}
{0x001b84, "Scan Engineering Telecom"}
{0x001b85, "MAN Diesel SE"}
{0x001b86, "Bosch Access Systems GmbH"}
{0x001b87, "Deepsound Tech. Co."}
{0x001b88, "Divinet Access Technologies"}
{0x001b89, "Emza Visual Sense"}
{0x001b8a, "2M Electronic A/S"}
{0x001b8b, "NEC AccessTechnica"}
{0x001b8c, "JMicron Technology"}
{0x001b8d, "Electronic Computer Systems"}
{0x001b8e, "Hulu Sweden AB"}
{0x001b8f, "Cisco Systems"}
{0x001b90, "Cisco Systems"}
{0x001b91, "Efkon AG"}
{0x001b92, "l-acoustics"}
{0x001b93, "JC Decaux SA DNT"}
{0x001b94, "T.E.M.A. S.p.A."}
{0x001b95, "Video Systems SRL"}
{0x001b96, "General Sensing"}
{0x001b97, "Violin Technologies"}
{0x001b98, "Samsung Electronics Co."}
{0x001b99, "KS System GmbH"}
{0x001b9a, "Apollo Fire Detectors"}
{0x001b9b, "Hose-McCann Communications"}
{0x001b9c, "Satel sp. z o.o."}
{0x001b9d, "Novus Security Sp. z o.o."}
{0x001b9e, "Askey  Computer "}
{0x001b9f, "Calyptech"}
{0x001ba0, "Awox"}
{0x001ba1, "mic AB"}
{0x001ba2, "IDS Imaging Development Systems GmbH"}
{0x001ba3, "Flexit Group GmbH"}
{0x001ba4, "S.A.E Afikim"}
{0x001ba5, "MyungMin Systems"}
{0x001ba6, "intotech"}
{0x001ba7, "Lorica Solutions"}
{0x001ba8, "Ubi&mobi"}
{0x001ba9, "Brother Industries"}
{0x001baa, "XenICs nv"}
{0x001bab, "Telchemy, Incorporated"}
{0x001bac, "Curtiss Wright Controls Embedded Computing"}
{0x001bad, "iControl Incorporated"}
{0x001bae, "Micro Control Systems"}
{0x001baf, "Nokia Danmark A/S"}
{0x001bb0, "Bharat Electronics"}
{0x001bb1, "Wistron Neweb"}
{0x001bb2, "Intellect International NV"}
{0x001bb3, "Condalo GmbH"}
{0x001bb4, "Airvod Limited"}
{0x001bb5, "ZF Electronics GmbH"}
{0x001bb6, "Bird Electronic"}
{0x001bb7, "Alta Heights Technology"}
{0x001bb8, "Blueway Electronic Co;ltd"}
{0x001bb9, "Elitegroup Computer System Co."}
{0x001bba, "Nortel"}
{0x001bbb, "RFTech Co."}
{0x001bbc, "Silver Peak Systems"}
{0x001bbd, "FMC Kongsberg Subsea AS"}
{0x001bbe, "Icop Digital"}
{0x001bbf, "Sagem Communication"}
{0x001bc0, "Juniper Networks"}
{0x001bc1, "Holux Technology"}
{0x001bc2, "Integrated Control Technology Limitied"}
{0x001bc3, "Mobisolution Co."}
{0x001bc4, "Ultratec"}
{0x001bc5, "Ieee Registration Authority"}
{0x001bc6, "Strato Rechenzentrum AG"}
{0x001bc7, "StarVedia Technology"}
{0x001bc8, "Miura Co."}
{0x001bc9, "FSN Display"}
{0x001bca, "Beijing Run Technology Company"}
{0x001bcb, "Pempek Systems"}
{0x001bcc, "Kingtek Cctv Alliance CO."}
{0x001bcd, "Daviscomms (S) PTE"}
{0x001bce, "Measurement Devices"}
{0x001bcf, "Dataupia"}
{0x001bd0, "Identec Solutions"}
{0x001bd1, "Sogestmatic"}
{0x001bd2, "Ultra-x Asia Pacific"}
{0x001bd3, "Matsushita Electric Panasonic AVC"}
{0x001bd4, "Cisco Systems"}
{0x001bd5, "Cisco Systems"}
{0x001bd6, "Kelvin Hughes"}
{0x001bd7, "Scientific Atlanta, A Cisco Company"}
{0x001bd8, "DVTel"}
{0x001bd9, "Edgewater Computer Systems"}
{0x001bda, "UTStarcom"}
{0x001bdb, "Valeo Vecs"}
{0x001bdc, "Vencer Co."}
{0x001bdd, "Motorola Mobility"}
{0x001bde, "Renkus-Heinz"}
{0x001bdf, "Iskra MIS"}
{0x001be0, "Telenot Electronic Gmbh"}
{0x001be1, "ViaLogy"}
{0x001be2, "AhnLab"}
{0x001be3, "Health Hero Network"}
{0x001be4, "Townet SRL"}
{0x001be5, "802automation Limited"}
{0x001be6, "VR AG"}
{0x001be7, "Postek Electronics Co."}
{0x001be8, "Ultratronik GmbH"}
{0x001be9, "Broadcom"}
{0x001bea, "Nintendo Co."}
{0x001beb, "DMP Electronics"}
{0x001bec, "Netio Technologies Co."}
{0x001bed, "Brocade Communications Systems"}
{0x001bee, "Nokia Danmark A/S"}
{0x001bef, "Blossoms Digital Technology Co."}
{0x001bf0, "Value Platforms Limited"}
{0x001bf1, "Nanjing SilverNet Software Co."}
{0x001bf2, "Kworld Computer CO."}
{0x001bf3, "Transradio Sendersysteme Berlin AG"}
{0x001bf4, "Kenwin Industrial(hk)"}
{0x001bf5, "Tellink Sistemas de Telecomunicacin S.L."}
{0x001bf6, "Conwise Technology"}
{0x001bf7, "Lund IP Products AB"}
{0x001bf8, "Digitrax"}
{0x001bf9, "Intellitect Water"}
{0x001bfa, "G.i.N. mbH"}
{0x001bfb, "Alps Electric Co."}
{0x001bfc, "Asustek Computer"}
{0x001bfd, "Dignsys"}
{0x001bfe, "Zavio"}
{0x001bff, "Millennia Media"}
{0x001c00, "Entry Point"}
{0x001c01, "ABB Oy Drives"}
{0x001c02, "Pano Logic"}
{0x001c03, "Betty TV Technology AG"}
{0x001c04, "Airgain"}
{0x001c05, "Nonin Medical"}
{0x001c06, "Siemens Numerical Control, Nanjing"}
{0x001c07, "Cwlinux Limited"}
{0x001c08, "Echo360"}
{0x001c09, "SAE Electronic Co."}
{0x001c0a, "Shenzhen AEE Technology Co."}
{0x001c0b, "SmartAnt Telecom"}
{0x001c0c, "Tanita"}
{0x001c0d, "G-Technology"}
{0x001c0e, "Cisco Systems"}
{0x001c0f, "Cisco Systems"}
{0x001c10, "Cisco-Linksys"}
{0x001c11, "Motorola Mobility"}
{0x001c12, "Motorola Mobility"}
{0x001c13, "Optsys Technology CO."}
{0x001c14, "VMware"}
{0x001c15, "TXP"}
{0x001c16, "ThyssenKrupp Elevator"}
{0x001c17, "Nortel"}
{0x001c18, "Sicert S.r.L."}
{0x001c19, "secunet Security Networks AG"}
{0x001c1a, "Thomas Instrumentation"}
{0x001c1b, "Hyperstone GmbH"}
{0x001c1c, "Center Communication Systems GmbH"}
{0x001c1d, "Chenzhou Gospell Digital Technology Co."}
{0x001c1e, "emtrion GmbH"}
{0x001c1f, "Quest Retail Technology"}
{0x001c20, "CLB Benelux"}
{0x001c21, "Nucsafe"}
{0x001c22, "Aeris Elettronica s.r.l."}
{0x001c23, "Dell"}
{0x001c24, "Formosa Wireless Systems"}
{0x001c25, "Hon Hai Precision Ind. Co."}
{0x001c26, "Hon Hai Precision Ind. Co."}
{0x001c27, "Sunell Electronics Co."}
{0x001c28, "Sphairon Technologies GmbH "}
{0x001c29, "Core Digital Electronics CO."}
{0x001c2a, "Envisacor Technologies"}
{0x001c2b, "Alertme.com Limited"}
{0x001c2c, "Synapse"}
{0x001c2d, "FlexRadio Systems"}
{0x001c2e, "ProCurve Networking by HP"}
{0x001c2f, "Pfister GmbH"}
{0x001c30, "Mode Lighting (UK"}
{0x001c31, "Mobile XP Technology Co."}
{0x001c32, "Telian"}
{0x001c33, "Sutron"}
{0x001c34, "Huey Chiao International CO."}
{0x001c35, "Nokia Danmark A/S"}
{0x001c36, "iNEWiT NV"}
{0x001c37, "Callpod"}
{0x001c38, "Bio-Rad Laboratories"}
{0x001c39, "S Netsystems"}
{0x001c3a, "Element Labs"}
{0x001c3b, "AmRoad Technology"}
{0x001c3c, "Seon Design"}
{0x001c3d, "WaveStorm"}
{0x001c3e, "ECKey Limited"}
{0x001c3f, "International Police Technologies"}
{0x001c40, "VDG-Security bv"}
{0x001c41, "scemtec Transponder Technology GmbH"}
{0x001c42, "Parallels"}
{0x001c43, "Samsung Electronics Co."}
{0x001c44, "Bosch Security Systems BV"}
{0x001c45, "Chenbro Micom Co."}
{0x001c46, "Qtum"}
{0x001c47, "Hangzhou Hollysys Automation Co."}
{0x001c48, "WiDeFi"}
{0x001c49, "Zoltan Technology"}
{0x001c4a, "AVM GmbH"}
{0x001c4b, "Gener8"}
{0x001c4c, "Petrotest Instruments"}
{0x001c4d, "Zeetoo"}
{0x001c4e, "Tasa International Limited"}
{0x001c4f, "Macab AB"}
{0x001c50, "TCL Technoly Electronics(Huizhou)Co."}
{0x001c51, "Celeno Communications"}
{0x001c52, "Visionee SRL"}
{0x001c53, "Synergy Lighting Controls"}
{0x001c54, "Hillstone Networks"}
{0x001c55, "Shenzhen Kaifa Technology Co."}
{0x001c56, "Pado Systems"}
{0x001c57, "Cisco Systems"}
{0x001c58, "Cisco Systems"}
{0x001c59, "Devon IT"}
{0x001c5a, "Advanced Relay"}
{0x001c5b, "Chubb Electronic Security Systems"}
{0x001c5c, "Integrated Medical Systems"}
{0x001c5d, "Leica Microsystems"}
{0x001c5e, "Aston France"}
{0x001c5f, "Winland Electronics"}
{0x001c60, "CSP Frontier Technologies"}
{0x001c61, "Galaxy Technology (HK)"}
{0x001c62, "LG Electronics"}
{0x001c63, "Truen"}
{0x001c64, "Cellnet+Hunt"}
{0x001c65, "JoeScan"}
{0x001c66, "Ucamp Co."}
{0x001c67, "Pumpkin Networks"}
{0x001c68, "Anhui Sun Create Electronics Co."}
{0x001c69, "Packet Vision"}
{0x001c6a, "Weiss Engineering"}
{0x001c6b, "Covax  Co."}
{0x001c6c, "Jabil Circuit (Guangzhou) Limited"}
{0x001c6d, "Kyohritsu Electronic Industry CO."}
{0x001c6e, "Newbury Networks"}
{0x001c6f, "Emfit"}
{0x001c70, "Novacomm Ltda"}
{0x001c71, "Emergent Electronics"}
{0x001c72, "Mayer & Cie GmbH & Co KG"}
{0x001c73, "Arista Networks"}
{0x001c74, "Syswan Technologies"}
{0x001c75, "RF Systems GmbH"}
{0x001c76, "The Wandsworth Group"}
{0x001c77, "Prodys"}
{0x001c78, "Wyplay SAS"}
{0x001c79, "Cohesive Financial Technologies"}
{0x001c7a, "Perfectone Netware Company"}
{0x001c7b, "Castlenet Technology"}
{0x001c7c, "Perq Systems"}
{0x001c7d, "Excelpoint Manufacturing Pte"}
{0x001c7e, "Toshiba"}
{0x001c7f, "Check Point Software Technologies"}
{0x001c80, "New Business Division/Rhea-Information CO."}
{0x001c81, "NextGen Venturi"}
{0x001c82, "Genew Technologies"}
{0x001c83, "New Level Telecom Co."}
{0x001c84, "STL Solution Co."}
{0x001c85, "Eunicorn"}
{0x001c86, "Cranite Systems"}
{0x001c87, "Uriver"}
{0x001c88, "Transystem"}
{0x001c89, "Force Communications"}
{0x001c8a, "Cirrascale"}
{0x001c8b, "MJ Innovations"}
{0x001c8c, "Dial Technology"}
{0x001c8d, "Mesa Imaging"}
{0x001c8e, "Alcatel-Lucent IPD"}
{0x001c8f, "Advanced Electronic Design"}
{0x001c90, "Empacket"}
{0x001c91, "Gefen"}
{0x001c92, "Tervela"}
{0x001c93, "ExaDigm"}
{0x001c94, "LI-COR Biosciences"}
{0x001c95, "Opticomm"}
{0x001c96, "Linkwise Technology Pte"}
{0x001c97, "Enzytek Technology,"}
{0x001c98, "Lucky Technology (hk) Company Limited"}
{0x001c99, "Shunra Software"}
{0x001c9a, "Nokia Danmark A/S"}
{0x001c9b, "Feig Electronic Gmbh"}
{0x001c9c, "Nortel"}
{0x001c9d, "Liecthi AG"}
{0x001c9e, "Dualtech IT AB"}
{0x001c9f, "Razorstream"}
{0x001ca0, "Production Resource Group"}
{0x001ca1, "Akamai Technologies"}
{0x001ca2, "ADB Broadband Italia"}
{0x001ca3, "Terra"}
{0x001ca4, "Sony Ericsson Mobile Communications"}
{0x001ca5, "Zygo"}
{0x001ca6, "Win4NET"}
{0x001ca7, "International Quartz Limited"}
{0x001ca8, "AirTies Wireless Networks"}
{0x001ca9, "Audiomatica Srl"}
{0x001caa, "Bellon"}
{0x001cab, "Meyer Sound Laboratories"}
{0x001cac, "Qniq Technology"}
{0x001cad, "Wuhan Telecommunication Devices Co."}
{0x001cae, "WiChorus"}
{0x001caf, "Plato Networks"}
{0x001cb0, "Cisco Systems"}
{0x001cb1, "Cisco Systems"}
{0x001cb2, "BPT SPA"}
{0x001cb3, "Apple"}
{0x001cb4, "Iridium Satellite"}
{0x001cb5, "Neihua Network Technology Co.,LTD.(NHN)"}
{0x001cb6, "Duzon CNT Co."}
{0x001cb7, "USC DigiArk"}
{0x001cb8, "CBC Co."}
{0x001cb9, "Kwang Sung Electronics CO."}
{0x001cba, "VerScient"}
{0x001cbb, "MusicianLink"}
{0x001cbc, "CastGrabber"}
{0x001cbd, "Ezze Mobile Tech."}
{0x001cbe, "Nintendo Co."}
{0x001cbf, "Intel Corporate"}
{0x001cc0, "Intel Corporate"}
{0x001cc1, "Motorola Mobility"}
{0x001cc2, "Part II Research"}
{0x001cc3, "Pace plc"}
{0x001cc4, "Hewlett-Packard Company"}
{0x001cc5, "3com"}
{0x001cc6, "ProStor Systems"}
{0x001cc7, "Rembrandt Technologies, D/b/a Remstream"}
{0x001cc8, "Industronic Industrie-electronic Gmbh & Co. KG"}
{0x001cc9, "Kaise Electronic Technology Co."}
{0x001cca, "Shanghai Gaozhi Science & Technology Development Co."}
{0x001ccb, "Forth Public Company Limited"}
{0x001ccc, "Research In Motion Limited"}
{0x001ccd, "Alektrona"}
{0x001cce, "By Techdesign"}
{0x001ccf, "Limetek"}
{0x001cd0, "Circleone Co."}
{0x001cd1, "Waves Audio"}
{0x001cd2, "King Champion (Hong Kong) Limited"}
{0x001cd3, "ZP Engineering SEL"}
{0x001cd4, "Nokia Danmark A/S"}
{0x001cd5, "ZeeVee"}
{0x001cd6, "Nokia Danmark A/S"}
{0x001cd7, "Harman/Becker Automotive Systems GmbH"}
{0x001cd8, "BlueAnt Wireless"}
{0x001cd9, "GlobalTop Technology"}
{0x001cda, "Exegin Technologies Limited"}
{0x001cdb, "Carpoint Co."}
{0x001cdc, "Custom Computer Services"}
{0x001cdd, "Cowbell Engineering CO."}
{0x001cde, "Interactive Multimedia eXchange"}
{0x001cdf, "Belkin International"}
{0x001ce0, "Dasan TPS"}
{0x001ce1, "Indra Sistemas"}
{0x001ce2, "Attero Tech"}
{0x001ce3, "Optimedical Systems"}
{0x001ce4, "EleSy JSC"}
{0x001ce5, "MBS Electronic Systems GmbH"}
{0x001ce6, "Innes"}
{0x001ce7, "Rocon PLC Research Centre"}
{0x001ce8, "Cummins"}
{0x001ce9, "Galaxy Technology Limited"}
{0x001cea, "Scientific-Atlanta"}
{0x001ceb, "Nortel"}
{0x001cec, "Mobilesoft (Aust.)"}
{0x001ced, "Environnement SA"}
{0x001cee, "Sharp"}
{0x001cef, "Primax Electronics"}
{0x001cf0, "D-Link"}
{0x001cf1, "SUPoX Technology Co. "}
{0x001cf2, "Tenlon Technology Co."}
{0x001cf3, "EVS Broadcast Equipment"}
{0x001cf4, "Media Technology Systems"}
{0x001cf5, "Wiseblue Technology Limited"}
{0x001cf6, "Cisco Systems"}
{0x001cf7, "AudioScience"}
{0x001cf8, "Parade Technologies"}
{0x001cf9, "Cisco Systems"}
{0x001cfa, "Alarm.com"}
{0x001cfb, "Motorola Mobility"}
{0x001cfc, "Suminet Communication Technologies (Shanghai) Co."}
{0x001cfd, "Universal Electronics"}
{0x001cfe, "Quartics"}
{0x001cff, "Napera Networks"}
{0x001d00, "Brivo Systems"}
{0x001d01, "Neptune Digital"}
{0x001d02, "Cybertech Telecom Development"}
{0x001d03, "Design Solutions"}
{0x001d04, "Zipit Wireless"}
{0x001d05, "iLight"}
{0x001d06, "HM Electronics"}
{0x001d07, "Shenzhen Sang Fei Consumer Communications Co."}
{0x001d08, "Jiangsu Yinhe Electronics CO."}
{0x001d09, "Dell"}
{0x001d0a, "Davis Instruments"}
{0x001d0b, "Power Standards Lab"}
{0x001d0c, "MobileCompia"}
{0x001d0d, "Sony Computer Entertainment"}
{0x001d0e, "Agapha Technology co."}
{0x001d0f, "Tp-link Technologies Co."}
{0x001d10, "LightHaus Logic"}
{0x001d11, "Analogue & Micro"}
{0x001d12, "Rohm CO."}
{0x001d13, "NextGTV"}
{0x001d14, "Speradtone Information Technology Limited"}
{0x001d15, "Shenzhen Dolphin Electronic Co."}
{0x001d16, "Efixo"}
{0x001d17, "Digital Sky"}
{0x001d18, "Power Innovation GmbH"}
{0x001d19, "Arcadyan Technology"}
{0x001d1a, "OvisLink S.A."}
{0x001d1b, "Sangean Electronics"}
{0x001d1c, "Gennet s.a."}
{0x001d1d, "Inter-M"}
{0x001d1e, "Kyushu TEN Co."}
{0x001d1f, "Siauliu Tauro Televizoriai"}
{0x001d20, "Comtrend CO."}
{0x001d21, "Alcad SL"}
{0x001d22, "Foss Analytical A/S"}
{0x001d23, "Sensus"}
{0x001d24, "Aclara Power-Line Systems"}
{0x001d25, "Samsung Electronics Co."}
{0x001d26, "Rockridgesound Technology Co."}
{0x001d27, "Nac-intercom"}
{0x001d28, "Sony Ericsson Mobile Communications AB"}
{0x001d29, "Doro AB"}
{0x001d2a, "Tideway Electronic"}
{0x001d2b, "Wuhan Pont Technology CO. "}
{0x001d2c, "Wavetrend Technologies (Pty) Limited"}
{0x001d2d, "Pylone"}
{0x001d2e, "Ruckus Wireless"}
{0x001d2f, "QuantumVision"}
{0x001d30, "YX Wireless S.A."}
{0x001d31, "Highpro International R&D Co"}
{0x001d32, "Longkay Communication & Technology (Shanghai) Co."}
{0x001d33, "Maverick Systems"}
{0x001d34, "Syris Technology"}
{0x001d35, "Viconics Electronics"}
{0x001d36, "Electronics OF India Limited"}
{0x001d37, "Thales-Panda Transportation System"}
{0x001d38, "Seagate Technology"}
{0x001d39, "Moohadigital CO."}
{0x001d3a, "mh acoustics"}
{0x001d3b, "Nokia Danmark A/S"}
{0x001d3c, "Muscle"}
{0x001d3d, "Avidyne"}
{0x001d3e, "Saka Techno Science Co."}
{0x001d3f, "Mitron"}
{0x001d40, "Living Independently Group"}
{0x001d41, "Hardy Instruments"}
{0x001d42, "Nortel"}
{0x001d43, "Shenzhen G-link Digital Technology Co."}
{0x001d44, "Krohne"}
{0x001d45, "Cisco Systems"}
{0x001d46, "Cisco Systems"}
{0x001d47, "Covote GmbH & Co KG"}
{0x001d48, "Sensor-Technik Wiedemann GmbH"}
{0x001d49, "Innovation Wireless"}
{0x001d4a, "Carestream Health"}
{0x001d4b, "Grid Connect"}
{0x001d4c, "Alcatel-Lucent"}
{0x001d4d, "Adaptive Recognition Hungary"}
{0x001d4e, "TCM Mobile"}
{0x001d4f, "Apple Computer"}
{0x001d50, "Spinetix SA"}
{0x001d51, "Babcock & Wilcox Power Generation Group"}
{0x001d52, "Defzone B.V."}
{0x001d53, "S&O Electronics (Malaysia) Sdn. Bhd."}
{0x001d54, "Sunnic Technology & Merchandise"}
{0x001d55, "Zantaz"}
{0x001d56, "Kramer Electronics"}
{0x001d57, "Caetec Messtechnik"}
{0x001d58, "CQ"}
{0x001d59, "Mitra Energy & Infrastructure"}
{0x001d5a, "2Wire"}
{0x001d5b, "Tecvan Informatica Ltda"}
{0x001d5c, "Tom Communication Industrial Co."}
{0x001d5d, "Control Dynamics"}
{0x001d5e, "Coming Media"}
{0x001d5f, "Overspeed Sarl"}
{0x001d60, "Asustek Computer"}
{0x001d61, "BIJ"}
{0x001d62, "InPhase Technologies"}
{0x001d63, "Miele & Cie. KG"}
{0x001d64, "Adam Communications Systems Int"}
{0x001d65, "Microwave Radio Communications"}
{0x001d66, "Hyundai Telecom"}
{0x001d67, "Amec"}
{0x001d68, "Thomson Telecom Belgium"}
{0x001d69, "Knorr-Bremse AG"}
{0x001d6a, "Alpha Networks"}
{0x001d6b, "Motorola (formerly Netopia"}
{0x001d6c, "ClariPhy Communications"}
{0x001d6d, "Confidant International"}
{0x001d6e, "Nokia Danmark A/S"}
{0x001d6f, "Chainzone Technology Co."}
{0x001d70, "Cisco Systems"}
{0x001d71, "Cisco Systems"}
{0x001d72, "Wistron"}
{0x001d73, "Buffalo"}
{0x001d74, "Tianjin China-Silicon Microelectronics Co."}
{0x001d75, "Radioscape PLC"}
{0x001d76, "Eyeheight"}
{0x001d77, "NSGate"}
{0x001d78, "Invengo Information Technology Co."}
{0x001d79, "Signamax"}
{0x001d7a, "Wideband Semiconductor"}
{0x001d7b, "Ice Energy"}
{0x001d7c, "ABE Elettronica S.p.A."}
{0x001d7d, "Giga-byte Technology Co."}
{0x001d7e, "Cisco-Linksys"}
{0x001d7f, "Tekron International"}
{0x001d80, "Beijing Huahuan Eletronics Co."}
{0x001d81, "Guangzhou Gateway Electronics CO."}
{0x001d82, "GN A/S (GN Netcom A/S)"}
{0x001d83, "Emitech"}
{0x001d84, "Gateway"}
{0x001d85, "Call Direct Cellular Solutions"}
{0x001d86, "Shinwa Industries(China)"}
{0x001d87, "VigTech Labs Sdn Bhd"}
{0x001d88, "Clearwire"}
{0x001d89, "VaultStor"}
{0x001d8a, "TechTrex"}
{0x001d8b, "ADB Broadband Italia"}
{0x001d8c, "La Crosse Technology"}
{0x001d8d, "Raytek GmbH"}
{0x001d8e, "Alereon"}
{0x001d8f, "PureWave Networks"}
{0x001d90, "Emco Flow Systems"}
{0x001d91, "Digitize"}
{0x001d92, "Micro-star Int'l Co."}
{0x001d93, "Modacom"}
{0x001d94, "Climax Technology Co."}
{0x001d95, "Flash"}
{0x001d96, "WatchGuard Video"}
{0x001d97, "Alertus Technologies"}
{0x001d98, "Nokia Danmark A/S"}
{0x001d99, "Cyan Optic"}
{0x001d9a, "Godex International CO."}
{0x001d9b, "Hokuyo Automatic Co."}
{0x001d9c, "Rockwell Automation"}
{0x001d9d, "Artjoy International Limited"}
{0x001d9e, "Axion Technologies"}
{0x001d9f, "Matt   R.p.traczynscy Sp.J."}
{0x001da0, "Heng Yu Electronic Manufacturing Company Limited"}
{0x001da1, "Cisco Systems"}
{0x001da2, "Cisco Systems"}
{0x001da3, "SabiOso"}
{0x001da4, "Hangzhou System Technology CO."}
{0x001da5, "WB Electronics"}
{0x001da6, "Media Numerics Limited"}
{0x001da7, "Seamless Internet"}
{0x001da8, "Takahata Electronics Co."}
{0x001da9, "Castles Technology, Co."}
{0x001daa, "DrayTek"}
{0x001dab, "SwissQual License AG"}
{0x001dac, "Gigamon Systems"}
{0x001dad, "Sinotech Engineering Consultants,  Geotechnical Enginee"}
{0x001dae, "Chang Tseng Technology CO."}
{0x001daf, "Nortel"}
{0x001db0, "FuJian HengTong Information Technology Co."}
{0x001db1, "Crescendo Networks"}
{0x001db2, "Hokkaido Electric Engineering Co."}
{0x001db3, "ProCurve Networking by HP"}
{0x001db4, "Kumho ENG Co."}
{0x001db5, "Juniper networks"}
{0x001db6, "BestComm Networks"}
{0x001db7, "Tendril Networks"}
{0x001db8, "Intoto"}
{0x001db9, "Wellspring Wireless"}
{0x001dba, "Sony"}
{0x001dbb, "Dynamic System Electronics"}
{0x001dbc, "Nintendo Co."}
{0x001dbd, "Versamed"}
{0x001dbe, "Motorola Mobility"}
{0x001dbf, "Radiient Technologies"}
{0x001dc0, "Enphase Energy"}
{0x001dc1, "Audinate"}
{0x001dc2, "Xortec OY"}
{0x001dc3, "Rikor TV"}
{0x001dc4, "Aioi Systems Co."}
{0x001dc5, "Beijing Jiaxun Feihong Electricial Co."}
{0x001dc6, "SNR"}
{0x001dc7, "L-3 Communications Geneva Aerospace"}
{0x001dc8, "ScadaMetrcs"}
{0x001dc9, "GainSpan"}
{0x001dca, "PAV Electronics Limited"}
{0x001dcb, "Exns Development Oy"}
{0x001dcc, "Hetra Secure Solutions"}
{0x001dcd, "Arris Group"}
{0x001dce, "Arris Group"}
{0x001dcf, "Arris Group"}
{0x001dd0, "Arris Group"}
{0x001dd1, "Arris Group"}
{0x001dd2, "Arris Group"}
{0x001dd3, "Arris Group"}
{0x001dd4, "Arris Group"}
{0x001dd5, "Arris Group"}
{0x001dd6, "Arris Group"}
{0x001dd7, "Algolith"}
{0x001dd8, "Microsoft"}
{0x001dd9, "Hon Hai Precision Ind.Co."}
{0x001dda, "Mikroelektronika spol. s r. o."}
{0x001ddb, "C-BEL"}
{0x001ddc, "HangZhou DeChangLong Tech&Info Co."}
{0x001ddd, "DAT H.K. Limited"}
{0x001dde, "Zhejiang Broadcast&Television Technology Co."}
{0x001ddf, "Sunitec Enterprise Co."}
{0x001de0, "Intel Corporate"}
{0x001de1, "Intel Corporate"}
{0x001de2, "Radionor Communications"}
{0x001de3, "Intuicom"}
{0x001de4, "Visioneered Image Systems"}
{0x001de5, "Cisco Systems"}
{0x001de6, "Cisco Systems"}
{0x001de7, "Marine Sonic Technology"}
{0x001de8, "Nikko Denki Tsushin Company(ndtc)"}
{0x001de9, "Nokia Danmark A/S"}
{0x001dea, "Commtest Instruments"}
{0x001deb, "Dinec International"}
{0x001dec, "Marusys"}
{0x001ded, "Grid Net"}
{0x001dee, "Nextvision Sistemas Digitais DE Televiso LTDA."}
{0x001def, "Trimm"}
{0x001df0, "Vidient Systems"}
{0x001df1, "Intego Systems"}
{0x001df2, "Netflix"}
{0x001df3, "SBS Science & Technology Co."}
{0x001df4, "Magellan Technology Limited"}
{0x001df5, "Sunshine Co"}
{0x001df6, "Samsung Electronics Co."}
{0x001df7, "R. Stahl Schaltgerte Gmbh"}
{0x001df8, "Webpro Vision Technology"}
{0x001df9, "Cybiotronics (Far East) Limited"}
{0x001dfa, "Fujian Landi Commercial Equipment Co."}
{0x001dfb, "Netcleus Systems"}
{0x001dfc, "Ksic"}
{0x001dfd, "Nokia Danmark A/S"}
{0x001dfe, "Palm"}
{0x001dff, "Network Critical Solutions"}
{0x001e00, "Shantou Institute of Ultrasonic Instruments"}
{0x001e01, "Renesas Technology Sales Co."}
{0x001e02, "Sougou Keikaku Kougyou Co."}
{0x001e03, "LiComm Co."}
{0x001e04, "Hanson Research"}
{0x001e05, "Xseed Technologies & Computing"}
{0x001e06, "Wibrain"}
{0x001e07, "Winy Technology Co."}
{0x001e08, "Centec Networks"}
{0x001e09, "Zefatek Co."}
{0x001e0a, "Syba Tech Limited"}
{0x001e0b, "Hewlett-Packard Company"}
{0x001e0c, "Sherwood Information Partners"}
{0x001e0d, "Micran"}
{0x001e0e, "Maxi View Holdings Limited"}
{0x001e0f, "Briot International"}
{0x001e10, "ShenZhen Huawei Communication Technologies Co."}
{0x001e11, "Elelux International"}
{0x001e12, "Ecolab"}
{0x001e13, "Cisco Systems"}
{0x001e14, "Cisco Systems"}
{0x001e15, "Beech Hill Electronics"}
{0x001e16, "Keytronix"}
{0x001e17, "STN BV"}
{0x001e18, "Radio Activity srl"}
{0x001e19, "Gtri"}
{0x001e1a, "Best Source Taiwan"}
{0x001e1b, "Digital Stream Technology"}
{0x001e1c, "SWS Australia Limited"}
{0x001e1d, "East Coast Datacom"}
{0x001e1e, "Honeywell Life Safety"}
{0x001e1f, "Nortel"}
{0x001e20, "Intertain"}
{0x001e21, "Qisda Co."}
{0x001e22, "Arvoo Imaging Products BV"}
{0x001e23, "Electronic Educational Devices"}
{0x001e24, "Zhejiang Bell Technology Co."}
{0x001e25, "Intek Digital"}
{0x001e26, "Digifriends Co."}
{0x001e27, "SBN Tech Co."}
{0x001e28, "Lumexis"}
{0x001e29, "Hypertherm"}
{0x001e2a, "Netgear"}
{0x001e2b, "Radio Systems Design"}
{0x001e2c, "CyVerse"}
{0x001e2d, "Stim"}
{0x001e2e, "Sirti S.p.a."}
{0x001e2f, "DiMoto"}
{0x001e30, "Shireen"}
{0x001e31, "Infomark Co."}
{0x001e32, "Zensys"}
{0x001e33, "Inventec"}
{0x001e34, "CryptoMetrics"}
{0x001e35, "Nintendo Co."}
{0x001e36, "Ipte"}
{0x001e37, "Universal Global Scientific Industrial Co."}
{0x001e38, "Bluecard Software Technology Co."}
{0x001e39, "Comsys Communication"}
{0x001e3a, "Nokia Danmark A/S"}
{0x001e3b, "Nokia Danmark A/S"}
{0x001e3c, "Lyngbox Media AB"}
{0x001e3d, "Alps Electric Co."}
{0x001e3e, "KMW"}
{0x001e3f, "TrellisWare Technologies"}
{0x001e40, "Shanghai DareGlobal Technologies  Co."}
{0x001e41, "Microwave Communication & Component"}
{0x001e42, "Teltonika"}
{0x001e43, "Aisin AW Co."}
{0x001e44, "Santec"}
{0x001e45, "Sony Ericsson Mobile Communications AB"}
{0x001e46, "Motorola Mobility"}
{0x001e47, "PT. Hariff Daya Tunggal Engineering"}
{0x001e48, "Wi-Links"}
{0x001e49, "Cisco Systems"}
{0x001e4a, "Cisco Systems"}
{0x001e4b, "City Theatrical"}
{0x001e4c, "Hon Hai Precision Ind.Co."}
{0x001e4d, "Welkin Sciences"}
{0x001e4e, "Dako Edv-ingenieur- und Systemhaus Gmbh"}
{0x001e4f, "Dell"}
{0x001e50, "Battistoni Research"}
{0x001e51, "Converter Industry Srl"}
{0x001e52, "Apple Computer"}
{0x001e53, "Further Tech Co."}
{0x001e54, "Toyo Electric"}
{0x001e55, "Cowon Systems"}
{0x001e56, "Bally Wulff Entertainment GmbH"}
{0x001e57, "Alcoma, spol. s r.o."}
{0x001e58, "D-Link"}
{0x001e59, "Silicon Turnkey Express"}
{0x001e5a, "Motorola Mobility"}
{0x001e5b, "Unitron Company"}
{0x001e5c, "RB GeneralEkonomik"}
{0x001e5d, "Holosys d.o.o."}
{0x001e5e, "COmputime"}
{0x001e5f, "KwikByte"}
{0x001e60, "Digital Lighting Systems"}
{0x001e61, "Itec Gmbh"}
{0x001e62, "Siemon"}
{0x001e63, "Vibro-Meter SA"}
{0x001e64, "Intel Corporate"}
{0x001e65, "Intel Corporate"}
{0x001e66, "Resol Elektronische Regelungen Gmbh"}
{0x001e67, "Intel Corporate"}
{0x001e68, "Quanta Computer"}
{0x001e69, "Thomson"}
{0x001e6a, "Beijing Bluexon Technology Co."}
{0x001e6b, "Scientific Atlanta, A Cisco Company"}
{0x001e6c, "Carbon Mountain"}
{0x001e6d, "IT R&D Center"}
{0x001e6e, "Shenzhen First Mile Communications"}
{0x001e6f, "Magna-Power Electronics"}
{0x001e70, "Cobham Defence Communications"}
{0x001e71, "Igeacare Solutions"}
{0x001e72, "PCS"}
{0x001e73, "ZTE"}
{0x001e74, "Sagem Communication"}
{0x001e75, "LG Electronics"}
{0x001e76, "Thermo Fisher Scientific"}
{0x001e77, "Air2App"}
{0x001e78, "Owitek Technology,"}
{0x001e79, "Cisco Systems"}
{0x001e7a, "Cisco Systems"}
{0x001e7b, "R.I.CO. S.r.l."}
{0x001e7c, "Taiwick Limited"}
{0x001e7d, "Samsung Electronics Co."}
{0x001e7e, "Nortel"}
{0x001e7f, "CBM of America"}
{0x001e80, "Last Mile"}
{0x001e81, "CNB Technology"}
{0x001e82, "SanDisk "}
{0x001e83, "Lan/man Standards Association (lmsc)"}
{0x001e84, "Pika Technologies"}
{0x001e85, "Lagotek"}
{0x001e86, "MEL Co."}
{0x001e87, "Realease Limited"}
{0x001e88, "Andor System Support CO."}
{0x001e89, "Crfs Limited"}
{0x001e8a, "eCopy"}
{0x001e8b, "Infra Access Korea Co."}
{0x001e8c, "Asustek Computer"}
{0x001e8d, "Motorola Mobility"}
{0x001e8e, "Hunkeler AG"}
{0x001e8f, "Canon"}
{0x001e90, "Elitegroup Computer Systems Co"}
{0x001e91, "Kimin Electronic Co."}
{0x001e92, "Jeulin S.A."}
{0x001e93, "CiriTech Systems"}
{0x001e94, "Supercom Technology"}
{0x001e95, "Sigmalink"}
{0x001e96, "Sepura Plc"}
{0x001e97, "Medium Link System Technology CO."}
{0x001e98, "GreenLine Communications"}
{0x001e99, "Vantanol Industrial"}
{0x001e9a, "Hamilton Bonaduz AG"}
{0x001e9b, "San-Eisha"}
{0x001e9c, "Fidustron"}
{0x001e9d, "Recall Technologies"}
{0x001e9e, "ddm hopt + schuler Gmbh + Co. KG"}
{0x001e9f, "Visioneering Systems"}
{0x001ea0, "XLN-t"}
{0x001ea1, "Brunata a/s"}
{0x001ea2, "Symx Systems"}
{0x001ea3, "Nokia Danmark A/S"}
{0x001ea4, "Nokia Danmark A/S"}
{0x001ea5, "Robotous"}
{0x001ea6, "Best IT World (India) Pvt."}
{0x001ea7, "ActionTec Electronics"}
{0x001ea8, "Datang Mobile Communications Equipment CO."}
{0x001ea9, "Nintendo Co."}
{0x001eaa, "E-Senza Technologies GmbH"}
{0x001eab, "TeleWell Oy"}
{0x001eac, "Armadeus Systems"}
{0x001ead, "Wingtech Group Limited"}
{0x001eae, "Continental Automotive Systems"}
{0x001eaf, "Ophir Optronics"}
{0x001eb0, "ImesD Electronica S.L."}
{0x001eb1, "Cryptsoft"}
{0x001eb2, "LG innotek"}
{0x001eb3, "Primex Wireless"}
{0x001eb4, "Unifat Technology"}
{0x001eb5, "Ever Sparkle Technologies"}
{0x001eb6, "TAG Heuer SA"}
{0x001eb7, "TBTech, Co."}
{0x001eb8, "Fortis"}
{0x001eb9, "Sing Fai Technology Limited"}
{0x001eba, "High Density Devices AS"}
{0x001ebb, "Bluelight Technology"}
{0x001ebc, "Wintech Automation Co."}
{0x001ebd, "Cisco Systems"}
{0x001ebe, "Cisco Systems"}
{0x001ebf, "Haas Automation"}
{0x001ec0, "Microchip Technology"}
{0x001ec1, "3com Europe"}
{0x001ec2, "Apple"}
{0x001ec3, "Kozio"}
{0x001ec4, "Celio"}
{0x001ec5, "Middle Atlantic Products"}
{0x001ec6, "Obvius Holdings"}
{0x001ec7, "2Wire"}
{0x001ec8, "Rapid Mobile (Pty)"}
{0x001ec9, "Dell"}
{0x001eca, "Nortel"}
{0x001ecb, ""RPC "Energoautomatika""}
{0x001ecc, "Cdvi"}
{0x001ecd, "Kyland"}
{0x001ece, "Bisa Technologies (hong Kong) Limited"}
{0x001ecf, "Philips Electronics UK"}
{0x001ed0, "Connexium"}
{0x001ed1, "Keyprocessor B.V."}
{0x001ed2, "Ray Shine Video Technology"}
{0x001ed3, "Dot Technology Int'l Co."}
{0x001ed4, "Doble Engineering"}
{0x001ed5, "Tekon-Automatics"}
{0x001ed6, "Alentec & Orion AB"}
{0x001ed7, "H-Stream Wireless"}
{0x001ed8, "Digital United"}
{0x001ed9, "Mitsubishi Precision Co."}
{0x001eda, "Wesemann Elektrotechniek B.V."}
{0x001edb, "Giken Trastem Co."}
{0x001edc, "Sony Ericsson Mobile Communications AB"}
{0x001edd, "Wasko S.A."}
{0x001ede, "BYD Company Limited"}
{0x001edf, "Master Industrialization Center Kista"}
{0x001ee0, "Urmet Domus SpA"}
{0x001ee1, "Samsung Electronics Co."}
{0x001ee2, "Samsung Electronics Co."}
{0x001ee3, "T&W Electronics (ShenZhen) Co."}
{0x001ee4, "ACS Solutions France"}
{0x001ee5, "Cisco-Linksys"}
{0x001ee6, "Shenzhen Advanced Video Info-Tech Co."}
{0x001ee7, "Epic Systems"}
{0x001ee8, "Mytek"}
{0x001ee9, "Stoneridge Electronics AB"}
{0x001eea, "Sensor Switch"}
{0x001eeb, "Talk-A-Phone Co."}
{0x001eec, "Compal Information (kunshan) CO."}
{0x001eed, "Adventiq"}
{0x001eee, "ETL Systems"}
{0x001eef, "Cantronic International Limited"}
{0x001ef0, "Gigafin Networks"}
{0x001ef1, "Servimat"}
{0x001ef2, "Micro Motion"}
{0x001ef3, "From2"}
{0x001ef4, "L-3 Communications Display Systems"}
{0x001ef5, "Hitek Automated"}
{0x001ef6, "Cisco Systems"}
{0x001ef7, "Cisco Systems"}
{0x001ef8, "Emfinity"}
{0x001ef9, "Pascom Kommunikations systeme GmbH."}
{0x001efa, "Protei"}
{0x001efb, "Trio Motion Technology"}
{0x001efc, "JSC "massa-k""}
{0x001efd, "Microbit 2.0 AB"}
{0x001efe, "Level S.r.o."}
{0x001eff, "Mueller-Elektronik GmbH & Co. KG"}
{0x001f00, "Nokia Danmark A/S"}
{0x001f01, "Nokia Danmark A/S"}
{0x001f02, "Pixelmetrix Pte"}
{0x001f03, "NUM AG"}
{0x001f04, "Granch"}
{0x001f05, "iTAS Technology"}
{0x001f06, "Integrated Dispatch Solutions"}
{0x001f07, "Azteq Mobile"}
{0x001f08, "Risco"}
{0x001f09, "Jastec CO."}
{0x001f0a, "Nortel"}
{0x001f0b, "Federal State Unitary Enterprise Industrial Union"Electropribor""}
{0x001f0c, "Intelligent Digital Services GmbH"}
{0x001f0d, "L3 Communications - Telemetry West"}
{0x001f0e, "Japan Kyastem Co."}
{0x001f0f, "Select Engineered Systems"}
{0x001f10, "Toledo DO Brasil Industria DE Balancas  Ltda"}
{0x001f11, "Openmoko"}
{0x001f12, "Juniper Networks"}
{0x001f13, "S.& A.S."}
{0x001f14, "NexG"}
{0x001f15, "Bioscrypt"}
{0x001f16, "Wistron"}
{0x001f17, "IDX Company"}
{0x001f18, "Hakusan.Mfg.Co"}
{0x001f19, "Ben-ri Electronica S.A."}
{0x001f1a, "Prominvest"}
{0x001f1b, "RoyalTek Company"}
{0x001f1c, "Kobishi Electric Co."}
{0x001f1d, "Atlas Material Testing Technology"}
{0x001f1e, "Astec Technology Co."}
{0x001f1f, "Edimax Technology Co."}
{0x001f20, "Logitech Europe SA"}
{0x001f21, "Inner Mongolia Yin An Science & Technology Development Co."}
{0x001f22, "Source Photonics"}
{0x001f23, "Interacoustics"}
{0x001f24, "Digitview Technology CO."}
{0x001f25, "MBS GmbH"}
{0x001f26, "Cisco Systems"}
{0x001f27, "Cisco Systems"}
{0x001f28, "ProCurve Networking by HP"}
{0x001f29, "Hewlett-Packard Company"}
{0x001f2a, "Accm"}
{0x001f2b, "Orange Logic"}
{0x001f2c, "Starbridge Networks"}
{0x001f2d, "Electro-Optical Imaging"}
{0x001f2e, "Triangle Research Int'l Pte"}
{0x001f2f, "Berker GmbH & Co. KG"}
{0x001f30, "Travelping"}
{0x001f31, "Radiocomp"}
{0x001f32, "Nintendo Co."}
{0x001f33, "Netgear"}
{0x001f34, "Lung Hwa Electronics Co."}
{0x001f35, "Air802"}
{0x001f36, "Bellwin Information Co.,"}
{0x001f37, "Genesis I&C"}
{0x001f38, "Positron"}
{0x001f39, "Construcciones y Auxiliar de Ferrocarriles"}
{0x001f3a, "Hon Hai Precision Ind.Co."}
{0x001f3b, "Intel Corporate"}
{0x001f3c, "Intel Corporate"}
{0x001f3d, "Qbit GmbH"}
{0x001f3e, "RP-Technik e.K."}
{0x001f3f, "AVM GmbH"}
{0x001f40, "Speakercraft"}
{0x001f41, "Ruckus Wireless"}
{0x001f42, "Etherstack"}
{0x001f43, "Entes Elektronik"}
{0x001f44, "GE Transportation Systems"}
{0x001f45, "Enterasys"}
{0x001f46, "Nortel"}
{0x001f47, "MCS Logic"}
{0x001f48, "Mojix"}
{0x001f49, "Eurosat Distribution"}
{0x001f4a, "Albentia Systems S.A."}
{0x001f4b, "Lineage Power"}
{0x001f4c, "Roseman Engineering"}
{0x001f4d, "Segnetics"}
{0x001f4e, "ConMed Linvatec"}
{0x001f4f, "Thinkware Co."}
{0x001f50, "Swissdis AG"}
{0x001f51, "HD Communications"}
{0x001f52, "UVT Unternehmensberatung fr Verkehr und Technik GmbH"}
{0x001f53, "Gemac Gesellschaft Fr Mikroelektronikanwendung Chemnitz mbH"}
{0x001f54, "Lorex Technology"}
{0x001f55, "Honeywell Security (China) Co."}
{0x001f56, "Digital Forecast"}
{0x001f57, "Phonik Innovation Co."}
{0x001f58, "EMH Energiemesstechnik GmbH"}
{0x001f59, "Kronback Tracers"}
{0x001f5a, "Beckwith Electric Co."}
{0x001f5b, "Apple"}
{0x001f5c, "Nokia Danmark A/S"}
{0x001f5d, "Nokia Danmark A/S"}
{0x001f5e, "Dyna Technology Co."}
{0x001f5f, "Blatand GmbH"}
{0x001f60, "Compass Systems"}
{0x001f61, "Talent Communication Networks"}
{0x001f62, "JSC "Stilsoft""}
{0x001f63, "JSC Goodwin-Europa"}
{0x001f64, "Beijing Autelan Technology"}
{0x001f65, "Korea Electric Terminal CO."}
{0x001f66, "Planar"}
{0x001f67, "Hitachi"}
{0x001f68, "Martinsson Elektronik AB"}
{0x001f69, "Pingood Technology Co."}
{0x001f6a, "PacketFlux Technologies"}
{0x001f6b, "LG Electronics"}
{0x001f6c, "Cisco Systems"}
{0x001f6d, "Cisco Systems"}
{0x001f6e, "Vtech Engineering"}
{0x001f6f, "Fujian Sunnada Communication Co."}
{0x001f70, "Botik Technologies"}
{0x001f71, "xG Technology"}
{0x001f72, "QingDao Hiphone Technology Co"}
{0x001f73, "Teraview Technology Co."}
{0x001f74, "Eigen Development"}
{0x001f75, "GiBahn Media"}
{0x001f76, "AirLogic Systems"}
{0x001f77, "Heol Design"}
{0x001f78, "Blue Fox Porini Textile"}
{0x001f79, "Lodam Electronics A/S"}
{0x001f7a, "WiWide"}
{0x001f7b, "TechNexion"}
{0x001f7c, "Witelcom AS"}
{0x001f7d, "embedded wireless GmbH"}
{0x001f7e, "Motorola Mobility"}
{0x001f7f, "Phabrix Limited"}
{0x001f80, "Lucas Holding bv"}
{0x001f81, "Accel Semiconductor"}
{0x001f82, "Cal-Comp Electronics & Communications Co."}
{0x001f83, "Teleplan Technology Services Sdn Bhd"}
{0x001f84, "Gigle Semiconductor"}
{0x001f85, "Apriva ISS"}
{0x001f86, "digEcor"}
{0x001f87, "Skydigital"}
{0x001f88, "FMS Force Measuring Systems AG"}
{0x001f89, "Signalion GmbH"}
{0x001f8a, "Ellion Digital"}
{0x001f8b, "Cache IQ"}
{0x001f8c, "CCS"}
{0x001f8d, "Ingenieurbuero Stark GmbH und Ko. KG"}
{0x001f8e, "Metris USA"}
{0x001f8f, "Shanghai Bellmann Digital Source Co."}
{0x001f90, "Actiontec Electronics"}
{0x001f91, "DBS Lodging Technologies"}
{0x001f92, "VideoIQ"}
{0x001f93, "Xiotech"}
{0x001f94, "Lascar Electronics"}
{0x001f95, "Sagem Communication"}
{0x001f96, "Aprotechltd"}
{0x001f97, "Bertana SRL"}
{0x001f98, "Daiichi-dentsu"}
{0x001f99, "Seronicsltd"}
{0x001f9a, "Nortel Networks"}
{0x001f9b, "Posbro"}
{0x001f9c, "Ledco"}
{0x001f9d, "Cisco Systems"}
{0x001f9e, "Cisco Systems"}
{0x001f9f, "Thomson Telecom Belgium"}
{0x001fa0, "A10 Networks"}
{0x001fa1, "Gtran"}
{0x001fa2, "Datron World Communications"}
{0x001fa3, "T&W Electronics(Shenzhen)Co."}
{0x001fa4, "ShenZhen Gongjin Electronics Co."}
{0x001fa5, "Blue-White Industries"}
{0x001fa6, "Stilo srl"}
{0x001fa7, "Sony Computer Entertainment"}
{0x001fa8, "Smart Energy Instruments"}
{0x001fa9, "Atlanta DTH"}
{0x001faa, "Taseon"}
{0x001fab, "I.S High Tech.inc"}
{0x001fac, "Goodmill Systems"}
{0x001fad, "Brown Innovations"}
{0x001fae, "Blick South Africa (Pty)"}
{0x001faf, "NextIO"}
{0x001fb0, "TimeIPS"}
{0x001fb1, "Cybertech"}
{0x001fb2, "Sontheim Industrie Elektronik GmbH"}
{0x001fb3, "2Wire"}
{0x001fb4, "SmartShare Systems"}
{0x001fb5, "I/O Interconnect"}
{0x001fb6, "Chi Lin Technology Co."}
{0x001fb7, "WiMate Technologies"}
{0x001fb8, "Universal Remote Control"}
{0x001fb9, "Paltronics"}
{0x001fba, "BoYoung Tech. & Marketing"}
{0x001fbb, "Xenatech Co."}
{0x001fbc, "Evga"}
{0x001fbd, "Kyocera Wireless"}
{0x001fbe, "Shenzhen Mopnet Industrial Co."}
{0x001fbf, "Fulhua Microelectronics Taiwan Branch"}
{0x001fc0, "Control Express Finland Oy"}
{0x001fc1, "Hanlong Technology Co."}
{0x001fc2, "Jow Tong Technology Co"}
{0x001fc3, "SmartSynch"}
{0x001fc4, "Motorola Mobility"}
{0x001fc5, "Nintendo Co."}
{0x001fc6, "Asustek Computer"}
{0x001fc7, "Casio Hitachi Mobile Comunications Co."}
{0x001fc8, "Up-Today Industrial Co."}
{0x001fc9, "Cisco Systems"}
{0x001fca, "Cisco Systems"}
{0x001fcb, "NIW Solutions"}
{0x001fcc, "Samsung Electronics Co."}
{0x001fcd, "Samsung Electronics"}
{0x001fce, "Qtech"}
{0x001fcf, "MSI Technology GmbH"}
{0x001fd0, "Giga-byte Technology Co."}
{0x001fd1, "Optex Co."}
{0x001fd2, "Commtech Technology Macao Commercial Offshore"}
{0x001fd3, "Riva Networks"}
{0x001fd4, "4ipnet"}
{0x001fd5, "Microrisc S.r.o."}
{0x001fd6, "Shenzhen Allywll"}
{0x001fd7, "Telerad SA"}
{0x001fd8, "A-trust Computer"}
{0x001fd9, "RSD Communications"}
{0x001fda, "Nortel Networks"}
{0x001fdb, "Network Supply,"}
{0x001fdc, "Mobile Safe Track"}
{0x001fdd, "GDI"}
{0x001fde, "Nokia Danmark A/S"}
{0x001fdf, "Nokia Danmark A/S"}
{0x001fe0, "EdgeVelocity"}
{0x001fe1, "Hon Hai Precision Ind. Co."}
{0x001fe2, "Hon Hai Precision Ind. Co."}
{0x001fe3, "LG Electronics"}
{0x001fe4, "Sony Ericsson Mobile Communications"}
{0x001fe5, "In-Circuit GmbH"}
{0x001fe6, "Alphion"}
{0x001fe7, "Simet"}
{0x001fe8, "Kurusugawa Electronics Industry"}
{0x001fe9, "Printrex"}
{0x001fea, "Applied Media Technologies"}
{0x001feb, "Trio Datacom"}
{0x001fec, "Synapse lectronique"}
{0x001fed, "Tecan Systems"}
{0x001fee, "ubisys technologies GmbH"}
{0x001fef, "Shinsei Industries Co."}
{0x001ff0, "Audio Partnership"}
{0x001ff1, "Paradox Hellas S.A."}
{0x001ff2, "VIA Technologies"}
{0x001ff3, "Apple"}
{0x001ff4, "Power Monitors"}
{0x001ff5, "Kongsberg Defence & Aerospace"}
{0x001ff6, "PS Audio International"}
{0x001ff7, "Nakajima All Precision Co."}
{0x001ff8, "Siemens AG, Sector Industry, Drive Technologies, Motion Control Systems"}
{0x001ff9, "Advanced Knowledge Associates"}
{0x001ffa, "Coretree, Co"}
{0x001ffb, "Green Packet Bhd"}
{0x001ffc, "Riccius+Sohn GmbH"}
{0x001ffd, "Indigo Mobile Technologies"}
{0x001ffe, "ProCurve Networking by HP"}
{0x001fff, "Respironics"}
{0x002000, "Lexmark International"}
{0x002001, "DSP Solutions"}
{0x002002, "Seritech Enterprise CO."}
{0x002003, "Pixel Power"}
{0x002004, "Yamatake-honeywell CO."}
{0x002005, "Simple Technology"}
{0x002006, "Garrett Communications"}
{0x002007, "SFA"}
{0x002008, "Cable & Computer Technology"}
{0x002009, "Packard Bell Elec."}
{0x00200a, "Source-comm"}
{0x00200b, "Octagon Systems"}
{0x00200c, "Adastra Systems"}
{0x00200d, "Carl Zeiss"}
{0x00200e, "Satellite Technology MGMT"}
{0x00200f, "Tanbac CO."}
{0x002010, "Jeol System Technology CO."}
{0x002011, "Canopus CO."}
{0x002012, "Camtronics Medical Systems"}
{0x002013, "Diversified Technology"}
{0x002014, "Global View CO."}
{0x002015, "Actis Computer SA"}
{0x002016, "Showa Electric Wire & Cable CO"}
{0x002017, "Orbotech"}
{0x002018, "CIS Technology"}
{0x002019, "Ohler Gmbh"}
{0x00201a, "MRV Communications"}
{0x00201b, "Northern Telecom/network"}
{0x00201c, "Excel"}
{0x00201d, "Katana Products"}
{0x00201e, "Netquest"}
{0x00201f, "Best Power Technology"}
{0x002020, "Megatron Computer Industries"}
{0x002021, "Algorithms Software PVT."}
{0x002022, "NMS Communications"}
{0x002023, "T.C. Technologies"}
{0x002024, "Pacific Communication Sciences"}
{0x002025, "Control Technology"}
{0x002026, "Amkly Systems"}
{0x002027, "Ming Fortune Industry CO."}
{0x002028, "West EGG Systems"}
{0x002029, "Teleprocessing Products"}
{0x00202a, "N.V. Dzine"}
{0x00202b, "Advanced Telecommunications Modules"}
{0x00202c, "Welltronix CO."}
{0x00202d, "Taiyo"}
{0x00202e, "Daystar Digital"}
{0x00202f, "Zeta Communications"}
{0x002030, "Analog & Digital Systems"}
{0x002031, "Ertec Gmbh"}
{0x002032, "Alcatel Taisel"}
{0x002033, "Synapse Technologies"}
{0x002034, "Rotec Industrieautomation Gmbh"}
{0x002035, "IBM"}
{0x002036, "BMC Software"}
{0x002037, "Seagate Technology"}
{0x002038, "VME Microsystems International"}
{0x002039, "Scinets"}
{0x00203a, "Digital Bi0metrics"}
{0x00203b, "Wisdm"}
{0x00203c, "Eurotime AB"}
{0x00203d, "Honeywell ECC"}
{0x00203e, "LogiCan Technologies"}
{0x00203f, "Juki"}
{0x002040, "Motorola Broadband Communications Sector"}
{0x002041, "Data NET"}
{0x002042, "Datametrics"}
{0x002043, "Neuron Company Limited"}
{0x002044, "Genitech"}
{0x002045, "ION Networks"}
{0x002046, "Ciprico"}
{0x002047, "Steinbrecher"}
{0x002048, "Marconi Communications"}
{0x002049, "Comtron"}
{0x00204a, "Pronet Gmbh"}
{0x00204b, "Autocomputer CO."}
{0x00204c, "Mitron Computer PTE"}
{0x00204d, "Inovis Gmbh"}
{0x00204e, "Network Security Systems"}
{0x00204f, "Deutsche Aerospace AG"}
{0x002050, "Korea Computer"}
{0x002051, "Verilink"}
{0x002052, "Ragula Systems"}
{0x002053, "Huntsville Microsystems"}
{0x002054, "Sycamore Networks"}
{0x002055, "Altech CO."}
{0x002056, "Neoproducts"}
{0x002057, "Titze Datentechnik Gmbh"}
{0x002058, "Allied Signal"}
{0x002059, "Miro Computer Products AG"}
{0x00205a, "Computer Identics"}
{0x00205b, "Kentrox"}
{0x00205c, "InterNet Systems of Florida"}
{0x00205d, "Nanomatic OY"}
{0x00205e, "Castle ROCK"}
{0x00205f, "Gammadata Computer Gmbh"}
{0x002060, "Alcatel Italia S.p.a."}
{0x002061, "GarrettCom"}
{0x002062, "Scorpion Logic"}
{0x002063, "Wipro Infotech"}
{0x002064, "Protec Microsystems"}
{0x002065, "Supernet Networking"}
{0x002066, "General Magic"}
{0x002067, "Private"}
{0x002068, "Isdyne"}
{0x002069, "Isdn Systems"}
{0x00206a, "Osaka Computer"}
{0x00206b, "Konica Minolta Holdings"}
{0x00206c, "Evergreen Technology"}
{0x00206d, "Data RACE"}
{0x00206e, "XACT"}
{0x00206f, "Flowpoint"}
{0x002070, "Hynet"}
{0x002071, "IBR Gmbh"}
{0x002072, "Worklink Innovations"}
{0x002073, "Fusion Systems"}
{0x002074, "Sungwoon Systems"}
{0x002075, "Motorola Communication Israel"}
{0x002076, "Reudo"}
{0x002077, "Kardios Systems"}
{0x002078, "Runtop"}
{0x002079, "Mikron Gmbh"}
{0x00207a, "WiSE Communications"}
{0x00207b, "Intel"}
{0x00207c, "Autec Gmbh"}
{0x00207d, "Advanced Computer Applications"}
{0x00207e, "Finecom Co."}
{0x00207f, "Kyoei Sangyo CO."}
{0x002080, "Synergy (uk)"}
{0x002081, "Titan Electronics"}
{0x002082, "Oneac"}
{0x002083, "Presticom Incorporated"}
{0x002084, "OCE Printing Systems"}
{0x002085, "Exide Electronics"}
{0x002086, "Microtech Electronics Limited"}
{0x002087, "Memotec"}
{0x002088, "Global Village Communication"}
{0x002089, "T3plus Networking"}
{0x00208a, "Sonix Communications"}
{0x00208b, "Lapis Technologies"}
{0x00208c, "Galaxy Networks"}
{0x00208d, "CMD Technology"}
{0x00208e, "Chevin Software ENG."}
{0x00208f, "ECI Telecom"}
{0x002090, "Advanced Compression Technology"}
{0x002091, "J125, National Security Agency"}
{0x002092, "Chess Engineering B.V."}
{0x002093, "Landings Technology"}
{0x002094, "Cubix"}
{0x002095, "Riva Electronics"}
{0x002096, "Invensys"}
{0x002097, "Applied Signal Technology"}
{0x002098, "Hectronic AB"}
{0x002099, "BON Electric CO."}
{0x00209a, "THE 3DO Company"}
{0x00209b, "Ersat Electronic Gmbh"}
{0x00209c, "Primary Access"}
{0x00209d, "Lippert Automationstechnik"}
{0x00209e, "Brown's Operating System Services"}
{0x00209f, "Mercury Computer Systems"}
{0x0020a0, "OA Laboratory CO."}
{0x0020a1, "Dovatron"}
{0x0020a2, "Galcom Networking"}
{0x0020a3, "Divicom"}
{0x0020a4, "Multipoint Networks"}
{0x0020a5, "API Engineering"}
{0x0020a6, "Proxim Wireless"}
{0x0020a7, "Pairgain Technologies"}
{0x0020a8, "Sast Technology"}
{0x0020a9, "White Horse Industrial"}
{0x0020aa, "Digimedia Vision"}
{0x0020ab, "Micro Industries"}
{0x0020ac, "Interflex Datensysteme Gmbh"}
{0x0020ad, "Linq Systems"}
{0x0020ae, "Ornet Data Communication TECH."}
{0x0020af, "3com"}
{0x0020b0, "Gateway Devices"}
{0x0020b1, "Comtech Research"}
{0x0020b2, "GKD Gesellschaft Fur Kommunikation Und Datentechnik"}
{0x0020b3, "Scltec Communications Systems"}
{0x0020b4, "Terma Elektronik AS"}
{0x0020b5, "Yaskawa Electric"}
{0x0020b6, "Agile Networks"}
{0x0020b7, "Namaqua Computerware"}
{0x0020b8, "Prime Option"}
{0x0020b9, "Metricom"}
{0x0020ba, "Center FOR High Performance"}
{0x0020bb, "ZAX"}
{0x0020bc, "Long Reach Networks"}
{0x0020bd, "Niobrara R &"}
{0x0020be, "LAN Access"}
{0x0020bf, "Aehr Test Systems"}
{0x0020c0, "Pulse Electronics"}
{0x0020c1, "SAXA"}
{0x0020c2, "Texas Memory Systems"}
{0x0020c3, "Counter Solutions"}
{0x0020c4, "Inet"}
{0x0020c5, "Eagle Technology"}
{0x0020c6, "Nectec"}
{0x0020c7, "Akai Professional M.I."}
{0x0020c8, "Larscom Incorporated"}
{0x0020c9, "Victron BV"}
{0x0020ca, "Digital Ocean"}
{0x0020cb, "Pretec Electronics"}
{0x0020cc, "Digital Services"}
{0x0020cd, "Hybrid Networks"}
{0x0020ce, "Logical Design Group"}
{0x0020cf, "Test & Measurement Systems"}
{0x0020d0, "Versalynx"}
{0x0020d1, "Microcomputer Systems (M) SDN."}
{0x0020d2, "RAD Data Communications"}
{0x0020d3, "OST (ouest Standard Telematiqu"}
{0x0020d4, "Cabletron - Zeittnet"}
{0x0020d5, "Vipa Gmbh"}
{0x0020d6, "Breezecom"}
{0x0020d7, "Japan Minicomputer Systems CO."}
{0x0020d8, "Nortel Networks"}
{0x0020d9, "Panasonic Technologies,/mieco-us"}
{0x0020da, "Alcatel North America ESD"}
{0x0020db, "Xnet Technology"}
{0x0020dc, "Densitron Taiwan"}
{0x0020dd, "Cybertec"}
{0x0020de, "Japan Digital Laborat'yltd"}
{0x0020df, "Kyosan Electric MFG. CO."}
{0x0020e0, "Actiontec Electronics"}
{0x0020e1, "Alamar Electronics"}
{0x0020e2, "Information Resource Engineering"}
{0x0020e3, "MCD Kencom"}
{0x0020e4, "Hsing Tech Enterprise CO."}
{0x0020e5, "Apex DATA"}
{0x0020e6, "Lidkoping Machine Tools AB"}
{0x0020e7, "B&W Nuclear Service Company"}
{0x0020e8, "Datatrek"}
{0x0020e9, "Dantel"}
{0x0020ea, "Efficient Networks"}
{0x0020eb, "Cincinnati Microwave"}
{0x0020ec, "Techware Systems"}
{0x0020ed, "Giga-byte Technology CO."}
{0x0020ee, "Gtech"}
{0x0020ef, "USC"}
{0x0020f0, "Universal Microelectronics CO."}
{0x0020f1, "Altos India Limited"}
{0x0020f2, "Oracle "}
{0x0020f3, "Raynet"}
{0x0020f4, "Spectrix"}
{0x0020f5, "Pandatel AG"}
{0x0020f6, "NET TEK  AND Karlnet"}
{0x0020f7, "Cyberdata"}
{0x0020f8, "Carrera Computers"}
{0x0020f9, "Paralink Networks"}
{0x0020fa, "GDE Systems"}
{0x0020fb, "Octel Communications"}
{0x0020fc, "Matrox"}
{0x0020fd, "ITV Technologies"}
{0x0020fe, "Topware / Grand Computer"}
{0x0020ff, "Symmetrical Technologies"}
{0x002100, "GemTek Technology Co."}
{0x002101, "Aplicaciones Electronicas Quasar (AEQ)"}
{0x002102, "UpdateLogic"}
{0x002103, "GHI Electronics"}
{0x002104, "Gigaset Communications GmbH"}
{0x002105, "Alcatel-Lucent"}
{0x002106, "RIM Testing Services"}
{0x002107, "Seowonintech Co"}
{0x002108, "Nokia Danmark A/S"}
{0x002109, "Nokia Danmark A/S"}
{0x00210a, "byd:sign"}
{0x00210b, "Gemini Traze Rfid PVT."}
{0x00210c, "Cymtec Systems"}
{0x00210d, "Samsin Innotec"}
{0x00210e, "Orpak Systems L.T.D."}
{0x00210f, "Cernium"}
{0x002110, "Clearbox Systems"}
{0x002111, "Uniphone"}
{0x002112, "Wiscom System Co."}
{0x002113, "Padtec S/A"}
{0x002114, "Hylab Technology"}
{0x002115, "Phywe Systeme Gmbh & Co. KG"}
{0x002116, "Transcon Electronic Systems, spol. s r. o."}
{0x002117, "Tellord"}
{0x002118, "Athena Tech"}
{0x002119, "Samsung Electro-Mechanics"}
{0x00211a, "LInTech"}
{0x00211b, "Cisco Systems"}
{0x00211c, "Cisco Systems"}
{0x00211d, "Dataline AB"}
{0x00211e, "Motorola Mobility"}
{0x00211f, "Shinsung Deltatech Co."}
{0x002120, "Sequel Technologies"}
{0x002121, "VRmagic GmbH"}
{0x002122, "Chip-pro"}
{0x002123, "Aerosat Avionics"}
{0x002124, "Optos Plc"}
{0x002125, "KUK JE Tong Shin Co."}
{0x002126, "Shenzhen Torch Equipment Co."}
{0x002127, "Tp-link Technology Co."}
{0x002128, "Oracle"}
{0x002129, "Cisco-Linksys"}
{0x00212a, "Audiovox"}
{0x00212b, "MSA Auer"}
{0x00212c, "SemIndia System Private Limited"}
{0x00212d, "Scimolex"}
{0x00212e, "dresden-elektronik"}
{0x00212f, "Phoebe Micro"}
{0x002130, "Keico Hightech"}
{0x002131, "Blynke"}
{0x002132, "Masterclock"}
{0x002133, "Building"}
{0x002134, "Brandywine Communications"}
{0x002135, "Alcatel-lucent"}
{0x002136, "Motorola Mobility"}
{0x002137, "Bay Controls"}
{0x002138, "Cepheid"}
{0x002139, "Escherlogic"}
{0x00213a, "Winchester Systems"}
{0x00213b, "Berkshire Products"}
{0x00213c, "AliphCom"}
{0x00213d, "Cermetek Microelectronics"}
{0x00213e, "TomTom"}
{0x00213f, "A-Team Technology"}
{0x002140, "EN Technologies"}
{0x002141, "Radlive"}
{0x002142, "Advanced Control Systems doo"}
{0x002143, "Motorola Mobility"}
{0x002144, "SS Telecoms"}
{0x002145, "Semptian Technologies"}
{0x002146, "SCI Technology"}
{0x002147, "Nintendo Co."}
{0x002148, "Kaco Solar Korea"}
{0x002149, "China Daheng Group "}
{0x00214a, "Pixel Velocity"}
{0x00214b, "Shenzhen Hamp Science & Technology Co."}
{0x00214c, "Samsung Electronics CO."}
{0x00214d, "Guangzhou Skytone Transmission Technology Com."}
{0x00214e, "GS Yuasa Power Supply"}
{0x00214f, "Alps Electric Co."}
{0x002150, "Eyeview Electronics"}
{0x002151, "Millinet Co."}
{0x002152, "General Satellite Research & Development Limited"}
{0x002153, "SeaMicro"}
{0x002154, "D-tacq Solutions"}
{0x002155, "Cisco Systems"}
{0x002156, "Cisco Systems"}
{0x002157, "National Datacast"}
{0x002158, "Style Flying Technology Co."}
{0x002159, "Juniper Networks"}
{0x00215a, "Hewlett-Packard Company"}
{0x00215b, "Inotive"}
{0x00215c, "Intel Corporate"}
{0x00215d, "Intel Corporate"}
{0x00215e, "IBM"}
{0x00215f, "Ihse Gmbh"}
{0x002160, "Hidea Solutions Co."}
{0x002161, "Yournet"}
{0x002162, "Nortel"}
{0x002163, "Askey Computer"}
{0x002164, "Special Design Bureau for Seismic Instrumentation"}
{0x002165, "Presstek"}
{0x002166, "NovAtel"}
{0x002167, "HWA JIN T&I"}
{0x002168, "iVeia"}
{0x002169, "Prologix"}
{0x00216a, "Intel Corporate"}
{0x00216b, "Intel Corporate"}
{0x00216c, "Odva"}
{0x00216d, "Soltech Co."}
{0x00216e, "Function ATI (Huizhou) Telecommunications Co."}
{0x00216f, "SymCom"}
{0x002170, "Dell"}
{0x002171, "Wesung TNC Co."}
{0x002172, "Seoultek Valley"}
{0x002173, "Ion Torrent Systems"}
{0x002174, "AvaLAN Wireless"}
{0x002175, "Pacific Satellite International"}
{0x002176, "YMax Telecom"}
{0x002177, "W. L. Gore & Associates"}
{0x002178, "Matuschek Messtechnik GmbH"}
{0x002179, "Iogear"}
{0x00217a, "Sejin Electron"}
{0x00217b, "Bastec AB"}
{0x00217c, "2Wire"}
{0x00217d, "Pyxis S.r.l."}
{0x00217e, "Telit Communication s.p.a"}
{0x00217f, "Intraco Technology Pte"}
{0x002180, "Motorola Mobility"}
{0x002181, "Si2 Microsystems Limited"}
{0x002182, "SandLinks Systems"}
{0x002183, "Vatech Hydro"}
{0x002184, "Powersoft SRL"}
{0x002185, "Micro-star Int'l Co."}
{0x002186, "Universal Global Scientific Industrial Co."}
{0x002187, "Imacs GmbH"}
{0x002188, "EMC"}
{0x002189, "AppTech"}
{0x00218a, "Electronic Design and Manufacturing Company"}
{0x00218b, "Wescon Technology"}
{0x00218c, "Topcontrol Gmbh"}
{0x00218d, "AP Router Ind. Eletronica Ltda"}
{0x00218e, "Mekics CO."}
{0x00218f, "Avantgarde Acoustic Lautsprechersysteme GmbH"}
{0x002190, "Goliath Solutions"}
{0x002191, "D-Link"}
{0x002192, "Baoding Galaxy Electronic Technology  Co."}
{0x002193, "Videofon MV"}
{0x002194, "Ping Communication"}
{0x002195, "GWD Media Limited"}
{0x002196, "Telsey  S.p.A."}
{0x002197, "Elitegroup Computer System"}
{0x002198, "Thai Radio Co"}
{0x002199, "Vacon Plc"}
{0x00219a, "Cambridge Visual Networks"}
{0x00219b, "Dell"}
{0x00219c, "Honeywld Technology"}
{0x00219d, "Adesys BV"}
{0x00219e, "Sony Ericsson Mobile Communications"}
{0x00219f, "Satel OY"}
{0x0021a0, "Cisco Systems"}
{0x0021a1, "Cisco Systems"}
{0x0021a2, "EKE-Electronics"}
{0x0021a3, "Micromint"}
{0x0021a4, "Dbii Networks"}
{0x0021a5, "Erlphase Power Technologies"}
{0x0021a6, "Videotec Spa"}
{0x0021a7, "Hantle System Co."}
{0x0021a8, "Telephonics"}
{0x0021a9, "Mobilink Telecom Co."}
{0x0021aa, "Nokia Danmark A/S"}
{0x0021ab, "Nokia Danmark A/S"}
{0x0021ac, "Infrared Integrated Systems"}
{0x0021ad, "Nordic ID Oy"}
{0x0021ae, "Alcatel-lucent France - WTD"}
{0x0021af, "Radio Frequency Systems"}
{0x0021b0, "Tyco Telecommunications"}
{0x0021b1, "Digital Solutions"}
{0x0021b2, "Fiberblaze A/S"}
{0x0021b3, "Ross Controls"}
{0x0021b4, "Apro Media CO."}
{0x0021b5, "Vyro Games Limited"}
{0x0021b6, "Triacta Power Technologies"}
{0x0021b7, "Lexmark International"}
{0x0021b8, "Inphi"}
{0x0021b9, "Universal Devices"}
{0x0021ba, "Texas Instruments"}
{0x0021bb, "Riken Keiki Co."}
{0x0021bc, "Zala Computer"}
{0x0021bd, "Nintendo Co."}
{0x0021be, "Cisco, Service Provider Video Technology Group"}
{0x0021bf, "Hitachi High-Tech Control Systems"}
{0x0021c0, "Mobile Appliance"}
{0x0021c1, "ABB Oy / Distribution Automation"}
{0x0021c2, "GL Communications"}
{0x0021c3, "Cornell Communications"}
{0x0021c4, "Consilium AB"}
{0x0021c5, "3DSP"}
{0x0021c6, "CSJ Global"}
{0x0021c7, "Russound"}
{0x0021c8, "Lohuis Networks"}
{0x0021c9, "Wavecom Asia Pacific Limited"}
{0x0021ca, "ART System Co."}
{0x0021cb, "SMS Tecnologia Eletronica Ltda"}
{0x0021cc, "Flextronics International"}
{0x0021cd, "LiveTV"}
{0x0021ce, "NTC-Metrotek"}
{0x0021cf, "The Crypto Group"}
{0x0021d0, "Global Display Solutions Spa"}
{0x0021d1, "Samsung Electronics Co."}
{0x0021d2, "Samsung Electronics Co."}
{0x0021d3, "Bocom Security(asia Pacific) Limited"}
{0x0021d4, "Vollmer Werke GmbH"}
{0x0021d5, "X2E GmbH"}
{0x0021d6, "LXI Consortium"}
{0x0021d7, "Cisco Systems"}
{0x0021d8, "Cisco Systems"}
{0x0021d9, "Sekonic"}
{0x0021da, "Automation Products Group"}
{0x0021db, "Santachi Video Technology (Shenzhen) Co."}
{0x0021dc, "Tecnoalarm S.r.l."}
{0x0021dd, "Northstar Systems"}
{0x0021de, "Firepro Wireless"}
{0x0021df, "Martin Christ GmbH"}
{0x0021e0, "CommAgility"}
{0x0021e1, "Nortel Networks"}
{0x0021e2, "Creative Electronic GmbH"}
{0x0021e3, "SerialTek"}
{0x0021e4, "I-win"}
{0x0021e5, "Display Solution AG"}
{0x0021e6, "Starlight Video Limited"}
{0x0021e7, "Informatics Services"}
{0x0021e8, "Murata Manufacturing Co."}
{0x0021e9, "Apple"}
{0x0021ea, "Bystronic Laser AG"}
{0x0021eb, "ESP Systems"}
{0x0021ec, "Solutronic GmbH"}
{0x0021ed, "Telegesis"}
{0x0021ee, "Full Spectrum"}
{0x0021ef, "Kapsys"}
{0x0021f0, "EW3 Technologies"}
{0x0021f1, "Tutus Data AB"}
{0x0021f2, "Easy3call Technology Limited"}
{0x0021f3, "Si14 SpA"}
{0x0021f4, "INRange Systems"}
{0x0021f5, "Western Engravers Supply"}
{0x0021f6, "Oracle"}
{0x0021f7, "ProCurve Networking by HP"}
{0x0021f8, "Enseo"}
{0x0021f9, "Wirecom Technologies"}
{0x0021fa, "A4SP Technologies"}
{0x0021fb, "LG Electronics"}
{0x0021fc, "Nokia Danmark A/S"}
{0x0021fd, "Dsta S.L."}
{0x0021fe, "Nokia Danmark A/S"}
{0x0021ff, "Cyfrowy Polsat SA"}
{0x002200, "IBM"}
{0x002201, "Aksys Networks"}
{0x002202, "Excito Elektronik i Skne AB"}
{0x002203, "Glensound Electronics"}
{0x002204, "Koratek"}
{0x002205, "WeLink Solutions"}
{0x002206, "Cyberdyne"}
{0x002207, "Inteno Broadband Technology AB"}
{0x002208, "Certicom"}
{0x002209, "Omron Healthcare Co."}
{0x00220a, "OnLive"}
{0x00220b, "National Source Coding Center"}
{0x00220c, "Cisco Systems"}
{0x00220d, "Cisco Systems"}
{0x00220e, "Indigo Security Co."}
{0x00220f, "MoCA (Multimedia over Coax Alliance)"}
{0x002210, "Motorola Mobility"}
{0x002211, "Rohati Systems"}
{0x002212, "CAI Networks"}
{0x002213, "PCI"}
{0x002214, "Rinnai Korea"}
{0x002215, "Asustek Computer"}
{0x002216, "Shibaura Vending Machine"}
{0x002217, "Neat Electronics"}
{0x002218, "Verivue"}
{0x002219, "Dell"}
{0x00221a, "Audio Precision"}
{0x00221b, "Morega Systems"}
{0x00221c, "Private"}
{0x00221d, "Freegene Technology"}
{0x00221e, "Media Devices Co."}
{0x00221f, "eSang Technologies Co."}
{0x002220, "Mitac Technology"}
{0x002221, "Itoh Denki Co"}
{0x002222, "Schaffner Deutschland GmbH "}
{0x002223, "TimeKeeping Systems"}
{0x002224, "Good Will Instrument Co."}
{0x002225, "Thales Avionics"}
{0x002226, "Avaak"}
{0x002227, "uv-electronic GmbH"}
{0x002228, "Breeze Innovations"}
{0x002229, "Compumedics"}
{0x00222a, "SoundEar A/S"}
{0x00222b, "Nucomm"}
{0x00222c, "Ceton"}
{0x00222d, "SMC Networks"}
{0x00222e, "maintech GmbH"}
{0x00222f, "Open Grid Computing"}
{0x002230, "FutureLogic"}
{0x002231, "SMT&C Co."}
{0x002232, "Design Design Technology"}
{0x002233, "ADB Broadband Italia"}
{0x002234, "Corventis"}
{0x002235, "Strukton Systems bv"}
{0x002236, "Vector SP. Z O.O."}
{0x002237, "Shinhint Group"}
{0x002238, "Logiplus"}
{0x002239, "Indiana Life Sciences Incorporated"}
{0x00223a, "Scientific Atlanta, Cisco Spvt Group"}
{0x00223b, "Communication Networks"}
{0x00223c, "Ratio Entwicklungen Gmbh"}
{0x00223d, "JumpGen Systems"}
{0x00223e, "IRTrans GmbH"}
{0x00223f, "Netgear"}
{0x002240, "Universal Telecom S/A"}
{0x002241, "Apple"}
{0x002242, "Alacron"}
{0x002243, "AzureWave Technologies"}
{0x002244, "Chengdu Linkon Communications Device Co."}
{0x002245, "Leine & Linde AB"}
{0x002246, "Evoc Intelligent Technology Co."}
{0x002247, "DAC Engineering CO."}
{0x002248, "Microsoft"}
{0x002249, "Home Multienergy SL"}
{0x00224a, "Raylase AG"}
{0x00224b, "Airtech Technologies"}
{0x00224c, "Nintendo Co."}
{0x00224d, "Mitac International"}
{0x00224e, "SEEnergy"}
{0x00224f, "Byzoro Networks"}
{0x002250, "Point Six Wireless"}
{0x002251, "Lumasense Technologies"}
{0x002252, "Zoll Lifecor"}
{0x002253, "Entorian Technologies"}
{0x002254, "Bigelow Aerospace"}
{0x002255, "Cisco Systems"}
{0x002256, "Cisco Systems"}
{0x002257, "3Com Europe"}
{0x002258, "Taiyo Yuden Co."}
{0x002259, "Guangzhou New Postcom Equipment Co."}
{0x00225a, "Garde Security AB"}
{0x00225b, "Teradici"}
{0x00225c, "Multimedia & Communication Technology"}
{0x00225d, "Digicable Network India Pvt."}
{0x00225e, "Uwin Technologies Co."}
{0x00225f, "Liteon Technology"}
{0x002260, "Afreey"}
{0x002261, "Frontier Silicon"}
{0x002262, "BEP Marine"}
{0x002263, "Koos Technical Services"}
{0x002264, "Hewlett-Packard Company"}
{0x002265, "Nokia Danmark A/S"}
{0x002266, "Nokia Danmark A/S"}
{0x002267, "Nortel Networks"}
{0x002268, "Hon Hai Precision Ind. Co."}
{0x002269, "Hon Hai Precision Ind. Co."}
{0x00226a, "Honeywell"}
{0x00226b, "Cisco-Linksys"}
{0x00226c, "LinkSprite Technologies"}
{0x00226d, "Shenzhen Giec Electronics Co."}
{0x00226e, "Gowell Electronic Limited"}
{0x00226f, "3onedata Technology Co."}
{0x002270, "ABK North America"}
{0x002271, "Jger Computergesteuerte Messtechnik GmbH"}
{0x002272, "American Micro-Fuel Device"}
{0x002273, "Techway"}
{0x002274, "FamilyPhone AB"}
{0x002275, "Belkin International"}
{0x002276, "Triple EYE B.V."}
{0x002277, "NEC Australia"}
{0x002278, "Shenzhen  Tongfang Multimedia  Technology Co."}
{0x002279, "Nippon Conlux Co."}
{0x00227a, "Telecom Design"}
{0x00227b, "Apogee Labs"}
{0x00227c, "Woori SMT Co."}
{0x00227d, "YE Data"}
{0x00227e, "Chengdu 30Kaitian Communication IndustryLtd"}
{0x00227f, "Ruckus Wireless"}
{0x002280, "A2B Electronics AB"}
{0x002281, "Daintree Networks"}
{0x002282, "8086 Limited"}
{0x002283, "Juniper Networks"}
{0x002284, "Desay A&V Science AND Technology Co."}
{0x002285, "Nomus Comm Systems"}
{0x002286, "Astron"}
{0x002287, "Titan Wireless"}
{0x002288, "Sagrad"}
{0x002289, "Optosecurity"}
{0x00228a, "Teratronik elektronische systeme gmbh"}
{0x00228b, "Kensington Computer Products Group"}
{0x00228c, "Photon Europe GmbH"}
{0x00228d, "GBS Laboratories"}
{0x00228e, "Tv-numeric"}
{0x00228f, "Cnrs"}
{0x002290, "Cisco Systems"}
{0x002291, "Cisco Systems"}
{0x002292, "Cinetal"}
{0x002293, "ZTE"}
{0x002294, "Kyocera"}
{0x002295, "SGM Technology for lighting spa"}
{0x002296, "LinoWave"}
{0x002297, "Xmos Semiconductor"}
{0x002298, "Sony Ericsson Mobile Communications"}
{0x002299, "SeaMicro"}
{0x00229a, "Lastar"}
{0x00229b, "AverLogic Technologies"}
{0x00229c, "Verismo Networks"}
{0x00229d, "Pyung-hwa Ind.co."}
{0x00229e, "Social Aid Research Co."}
{0x00229f, "Sensys Traffic AB"}
{0x0022a0, "Delphi"}
{0x0022a1, "Huawei Symantec Technologies Co."}
{0x0022a2, "Xtramus Technologies"}
{0x0022a3, "California Eastern Laboratories"}
{0x0022a4, "2Wire"}
{0x0022a5, "Texas Instruments"}
{0x0022a6, "Sony Computer Entertainment America"}
{0x0022a7, "Tyco Electronics AMP GmbH"}
{0x0022a8, "Ouman Finland Oy"}
{0x0022a9, "LG Electronics"}
{0x0022aa, "Nintendo Co."}
{0x0022ab, "Shenzhen Turbosight Technology"}
{0x0022ac, "Hangzhou Siyuan Tech. Co."}
{0x0022ad, "Telesis Technologies"}
{0x0022ae, "Mattel"}
{0x0022af, "Safety Vision"}
{0x0022b0, "D-Link"}
{0x0022b1, "Elbit Systems"}
{0x0022b2, "4RF Communications"}
{0x0022b3, "Sei S.p.A."}
{0x0022b4, "Motorola Mobility"}
{0x0022b5, "Novita"}
{0x0022b6, "Superflow Technologies Group"}
{0x0022b7, "GSS Grundig SAT-Systems GmbH"}
{0x0022b8, "Norcott"}
{0x0022b9, "Analogix Seminconductor"}
{0x0022ba, "Huth Elektronik Systeme Gmbh"}
{0x0022bb, "beyerdynamic GmbH & Co. KG"}
{0x0022bc, "Jdsu France SAS"}
{0x0022bd, "Cisco Systems"}
{0x0022be, "Cisco Systems"}
{0x0022bf, "SieAmp Group of Companies"}
{0x0022c0, "Shenzhen Forcelink Electronic Co"}
{0x0022c1, "Active Storage"}
{0x0022c2, "Proview Eletronica do Brasil Ltda"}
{0x0022c3, "Zeeport Technology"}
{0x0022c4, "epro GmbH"}
{0x0022c5, "Inforson Co"}
{0x0022c6, "Sutus"}
{0x0022c7, "Segger Microcontroller Gmbh & Co. KG"}
{0x0022c8, "Applied Instruments"}
{0x0022c9, "Lenord, Bauer & Co GmbH"}
{0x0022ca, "Anviz Biometric Tech. Co."}
{0x0022cb, "Ionodes"}
{0x0022cc, "SciLog"}
{0x0022cd, "Ared Technology Co."}
{0x0022ce, "Cisco, Service Provider Video Technology Group"}
{0x0022cf, "Planex Communications"}
{0x0022d0, "Polar Electro Oy"}
{0x0022d1, "Albrecht Jung GmbH & Co. KG"}
{0x0022d2, "All Earth Comrcio de Eletrnicos LTDA."}
{0x0022d3, "Hub-Tech"}
{0x0022d4, "ComWorth Co."}
{0x0022d5, "Eaton Electrical Group Data Center Solutions - Pulizzi"}
{0x0022d6, "Cypak AB"}
{0x0022d7, "Nintendo Co."}
{0x0022d8, "Shenzhen GST Security and Safety Technology Limited"}
{0x0022d9, "Fortex Industrial"}
{0x0022da, "Anatek"}
{0x0022db, "Translogic"}
{0x0022dc, "Vigil Health Solutions"}
{0x0022dd, "Protecta Electronics"}
{0x0022de, "Oppo Digital"}
{0x0022df, "Tamuz Monitors"}
{0x0022e0, "Atlantic Software Technologies S.r.L."}
{0x0022e1, "Zort Labs"}
{0x0022e2, "Wabtec Transit Division"}
{0x0022e3, "Amerigon"}
{0x0022e4, "Apass Technology CO."}
{0x0022e5, "Fisher-Rosemount Systems"}
{0x0022e6, "Intelligent Data"}
{0x0022e7, "WPS Parking Systems"}
{0x0022e8, "Applition Co."}
{0x0022e9, "ProVision Communications"}
{0x0022ea, "Rustelcom"}
{0x0022eb, "Data Respons A/S"}
{0x0022ec, "Idealbt Technology"}
{0x0022ed, "TSI Power"}
{0x0022ee, "Algo Communication Products"}
{0x0022ef, "Ibis Tek"}
{0x0022f0, "3 Greens Aviation Limited"}
{0x0022f1, "Private"}
{0x0022f2, "SunPower"}
{0x0022f3, "Sharp"}
{0x0022f4, "Ampak Technology"}
{0x0022f5, "Advanced Realtime Tracking GmbH"}
{0x0022f6, "Syracuse Research"}
{0x0022f7, "Conceptronic"}
{0x0022f8, "Pima Electronic Systems"}
{0x0022f9, "Pollin Electronic GmbH"}
{0x0022fa, "Intel Corporate"}
{0x0022fb, "Intel Corporate"}
{0x0022fc, "Nokia Danmark A/S"}
{0x0022fd, "Nokia Danmark A/S"}
{0x0022fe, "Microprocessor Designs"}
{0x0022ff, "Nivis"}
{0x002300, "Cayee Computer"}
{0x002301, "Witron Technology Limited"}
{0x002302, "Cobalt Digital"}
{0x002303, "Lite-on IT"}
{0x002304, "Cisco Systems"}
{0x002305, "Cisco Systems"}
{0x002306, "Alps Electric Co."}
{0x002307, "Future Innovation Tech Co."}
{0x002308, "Arcadyan Technology"}
{0x002309, "Janam Technologies"}
{0x00230a, "Arburg Gmbh & Co KG"}
{0x00230b, "Motorola Mobility"}
{0x00230c, "Clover Electronics Co."}
{0x00230d, "Nortel Networks"}
{0x00230e, "Gorba AG"}
{0x00230f, "Hirsch Electronics"}
{0x002310, "LNC Technology Co."}
{0x002311, "Gloscom Co."}
{0x002312, "Apple"}
{0x002313, "Qool Technologies"}
{0x002314, "Intel Corporate"}
{0x002315, "Intel Corporate"}
{0x002316, "Kisan Electronics CO"}
{0x002317, "Lasercraft"}
{0x002318, "Toshiba"}
{0x002319, "Sielox"}
{0x00231a, "ITF Co."}
{0x00231b, "Danaher Motion - Kollmorgen"}
{0x00231c, "Fourier Systems"}
{0x00231d, "Deltacom Electronics"}
{0x00231e, "Cezzer Multimedia Technologies"}
{0x00231f, "Guangda Electronic & Telecommunication Technology Development Co."}
{0x002320, "Nicira Networks"}
{0x002321, "Avitech International"}
{0x002322, "Kiss Teknical Solutions"}
{0x002323, "Zylin AS"}
{0x002324, "G-pro Computer"}
{0x002325, "Iolan Holding"}
{0x002326, "Fujitsu Limited"}
{0x002327, "Shouyo Electronics CO."}
{0x002328, "Alcon Telecommunications CO."}
{0x002329, "DDRdrive"}
{0x00232a, "eonas IT-Beratung und -Entwicklung GmbH"}
{0x00232b, "IRD A/S"}
{0x00232c, "Senticare"}
{0x00232d, "SandForce"}
{0x00232e, "Kedah Electronics Engineering"}
{0x00232f, "Advanced Card Systems"}
{0x002330, "Dizipia"}
{0x002331, "Nintendo Co."}
{0x002332, "Apple"}
{0x002333, "Cisco Systems"}
{0x002334, "Cisco Systems"}
{0x002335, "Linkflex Co."}
{0x002336, "Metel S.r.o."}
{0x002337, "Global Star Solutions ULC"}
{0x002338, "OJ-Electronics A/S"}
{0x002339, "Samsung Electronics"}
{0x00233a, "Samsung Electronics Co."}
{0x00233b, "C-Matic Systems"}
{0x00233c, "Alflex"}
{0x00233d, "Novero holding B.V."}
{0x00233e, "Alcatel-Lucent-IPD"}
{0x00233f, "Purechoice"}
{0x002340, "MiX Telematics"}
{0x002341, "Siemens AG, Infrastructure & Cities Sector, Building Technologies Division"}
{0x002342, "Coffee Equipment Company"}
{0x002343, "TEM AG"}
{0x002344, "Objective Interface Systems"}
{0x002345, "Sony Ericsson Mobile Communications"}
{0x002346, "Vestac"}
{0x002347, "ProCurve Networking by HP"}
{0x002348, "Sagem Communication"}
{0x002349, "Helmholtz Centre Berlin for Material and Energy"}
{0x00234a, "Private"}
{0x00234b, "Inyuan Technology"}
{0x00234c, "KTC AB"}
{0x00234d, "Hon Hai Precision Ind. Co."}
{0x00234e, "Hon Hai Precision Ind. Co."}
{0x00234f, "Luminous Power Technologies Pvt."}
{0x002350, "LynTec"}
{0x002351, "2Wire"}
{0x002352, "Datasensor S.p.a."}
{0x002353, "F E T Elettronica snc"}
{0x002354, "Asustek Computer"}
{0x002355, "Kinco Automation(Shanghai)"}
{0x002356, "Packet Forensics"}
{0x002357, "Pitronot Technologies and Engineering P.T.E."}
{0x002358, "Systel SA"}
{0x002359, "Benchmark Electronics ( Thailand ) Public Company Limited"}
{0x00235a, "Compal Information (kunshan) CO."}
{0x00235b, "Gulfstream"}
{0x00235c, "Aprius"}
{0x00235d, "Cisco Systems"}
{0x00235e, "Cisco Systems"}
{0x00235f, "Silicon Micro Sensors GmbH"}
{0x002360, "Lookit Technology Co."}
{0x002361, "Unigen"}
{0x002362, "Goldline Controls"}
{0x002363, "Zhuhai RaySharp Technology Co."}
{0x002364, "Power Instruments Pte"}
{0x002365, "Elka-elektronik Gmbh"}
{0x002366, "Beijing Siasun Electronic System Co."}
{0x002367, "UniControls a.s."}
{0x002368, "Motorola"}
{0x002369, "Cisco-Linksys"}
{0x00236a, "ClearAccess"}
{0x00236b, "Xembedded"}
{0x00236c, "Apple"}
{0x00236d, "ResMed"}
{0x00236e, "Burster GmbH & Co KG"}
{0x00236f, "DAQ System"}
{0x002370, "Snell"}
{0x002371, "Soam Systel"}
{0x002372, "More Star Industrial Group Limited"}
{0x002373, "GridIron Systems"}
{0x002374, "Motorola Mobility"}
{0x002375, "Motorola Mobility"}
{0x002376, "HTC"}
{0x002377, "Isotek Electronics"}
{0x002378, "GN Netcom A/S"}
{0x002379, "Union Business Machines Co."}
{0x00237a, "RIM"}
{0x00237b, "Whdi"}
{0x00237c, "Neotion"}
{0x00237d, "Hewlett-Packard Company"}
{0x00237e, "Elster Gmbh"}
{0x00237f, "Plantronics"}
{0x002380, "Nanoteq"}
{0x002381, "Lengda Technology(Xiamen) Co."}
{0x002382, "Lih Rong Electronic Enterprise Co."}
{0x002383, "InMage Systems"}
{0x002384, "GGH Engineering s.r.l."}
{0x002385, "Antipode"}
{0x002386, "Tour & Andersson AB"}
{0x002387, "ThinkFlood"}
{0x002388, "V.T. Telematica S.p.a."}
{0x002389, "Hangzhou H3C Technologies Co."}
{0x00238a, "Ciena"}
{0x00238b, "Quanta Computer"}
{0x00238c, "Private"}
{0x00238d, "Techno Design Co."}
{0x00238e, "ADB Broadband Italia"}
{0x00238f, "Nidec Copal"}
{0x002390, "Algolware"}
{0x002391, "Maxian"}
{0x002392, "Proteus Industries"}
{0x002393, "Ajinextek"}
{0x002394, "Samjeon"}
{0x002395, "Motorola Mobility"}
{0x002396, "Andes Technology"}
{0x002397, "Westell Technologies"}
{0x002398, "Sky Control"}
{0x002399, "VD Division, Samsung Electronics Co."}
{0x00239a, "EasyData Software GmbH"}
{0x00239b, "Elster Solutions"}
{0x00239c, "Juniper Networks"}
{0x00239d, "Mapower Electronics Co."}
{0x00239e, "Jiangsu Lemote Technology Limited"}
{0x00239f, "Institut fr Prftechnik"}
{0x0023a0, "Hana CNS Co."}
{0x0023a1, "Trend Electronics"}
{0x0023a2, "Motorola Mobility"}
{0x0023a3, "Motorola Mobility"}
{0x0023a4, "New Concepts Development"}
{0x0023a5, "SageTV"}
{0x0023a6, "E-Mon"}
{0x0023a7, "Redpine Signals"}
{0x0023a8, "Marshall Electronics"}
{0x0023a9, "Beijing Detianquan Electromechanical Equipment Co."}
{0x0023aa, "HFR"}
{0x0023ab, "Cisco Systems"}
{0x0023ac, "Cisco Systems"}
{0x0023ad, "Xmark"}
{0x0023ae, "Dell"}
{0x0023af, "Motorola Mobility"}
{0x0023b0, "Comxion Technology"}
{0x0023b1, "Longcheer Technology (Singapore) Pte"}
{0x0023b2, "Intelligent Mechatronic Systems"}
{0x0023b3, "Lyyn AB"}
{0x0023b4, "Nokia Danmark A/S"}
{0x0023b5, "Ortana"}
{0x0023b6, "Securite Communications / Honeywell"}
{0x0023b7, "Q-Light Co."}
{0x0023b8, "Sichuan Jiuzhou Electronic Technology Co."}
{0x0023b9, "Eads Deutschland Gmbh"}
{0x0023ba, "Chroma"}
{0x0023bb, "Schmitt Industries"}
{0x0023bc, "EQ-SYS GmbH"}
{0x0023bd, "Digital Ally"}
{0x0023be, "Cisco Spvtg"}
{0x0023bf, "Mainpine"}
{0x0023c0, "Broadway Networks"}
{0x0023c1, "Securitas Direct AB"}
{0x0023c2, "Samsung Electronics. Co."}
{0x0023c3, "LogMeIn"}
{0x0023c4, "Lux Lumen"}
{0x0023c5, "Radiation Safety and Control Services"}
{0x0023c6, "SMC"}
{0x0023c7, "AVSystem"}
{0x0023c8, "Team-r"}
{0x0023c9, "Sichuan Tianyi Information Science & Technology Stock CO."}
{0x0023ca, "Behind The Set"}
{0x0023cb, "Shenzhen Full-join Technology Co."}
{0x0023cc, "Nintendo Co."}
{0x0023cd, "Tp-link Technologies CO."}
{0x0023ce, "Kita Denshi"}
{0x0023cf, "Cummins-allison"}
{0x0023d0, "Uniloc USA"}
{0x0023d1, "TRG"}
{0x0023d2, "Inhand Electronics"}
{0x0023d3, "AirLink WiFi Networking"}
{0x0023d4, "Texas Instruments"}
{0x0023d5, "Warema Electronic Gmbh"}
{0x0023d6, "Samsung Electronics Co."}
{0x0023d7, "Samsung Electronics"}
{0x0023d8, "Ball-It Oy"}
{0x0023d9, "Banner Engineering"}
{0x0023da, "Industrial Computer Source (Deutschland)GmbH"}
{0x0023db, "saxnet gmbh"}
{0x0023dc, "Benein"}
{0x0023dd, "Elgin S.A."}
{0x0023de, "Ansync"}
{0x0023df, "Apple"}
{0x0023e0, "INO Therapeutics"}
{0x0023e1, "Cavena Image Products AB"}
{0x0023e2, "SEA Signalisation"}
{0x0023e3, "Microtronic AG"}
{0x0023e4, "IPnect co."}
{0x0023e5, "IPaXiom Networks"}
{0x0023e6, "Pirkus"}
{0x0023e7, "Hinke A/S"}
{0x0023e8, "Demco"}
{0x0023e9, "F5 Networks"}
{0x0023ea, "Cisco Systems"}
{0x0023eb, "Cisco Systems"}
{0x0023ec, "Algorithmix GmbH"}
{0x0023ed, "Motorola CHS"}
{0x0023ee, "Motorola Mobility"}
{0x0023ef, "Zuend Systemtechnik AG"}
{0x0023f0, "Shanghai Jinghan Weighing Apparatus Co."}
{0x0023f1, "Sony Ericsson Mobile Communications"}
{0x0023f2, "TVLogic"}
{0x0023f3, "Glocom"}
{0x0023f4, "Masternaut"}
{0x0023f5, "Wilo SE"}
{0x0023f6, "Softwell Technology Co."}
{0x0023f7, "Private"}
{0x0023f8, "ZyXEL Communications"}
{0x0023f9, "Double-Take Software"}
{0x0023fa, "RG Nets"}
{0x0023fb, "IP Datatel"}
{0x0023fc, "Ultra Stereo Labs"}
{0x0023fd, "AFT Atlas Fahrzeugtechnik GmbH"}
{0x0023fe, "Biodevices"}
{0x0023ff, "Beijing Httc Technology"}
{0x002400, "Nortel Networks"}
{0x002401, "D-Link"}
{0x002402, "Op-Tection GmbH"}
{0x002403, "Nokia Danmark A/S"}
{0x002404, "Nokia Danmark A/S"}
{0x002405, "Dilog Nordic AB"}
{0x002406, "Pointmobile"}
{0x002407, "Telem SAS"}
{0x002408, "Pacific Biosciences"}
{0x002409, "The Toro Company"}
{0x00240a, "US Beverage Net"}
{0x00240b, "Virtual Computer"}
{0x00240c, "Delec Gmbh"}
{0x00240d, "OnePath Networks"}
{0x00240e, "Inventec Besta Co."}
{0x00240f, "Ishii Tool & Engineering"}
{0x002410, "Nueteq Technology"}
{0x002411, "PharmaSmart"}
{0x002412, "Benign Technologies Co"}
{0x002413, "Cisco Systems"}
{0x002414, "Cisco Systems"}
{0x002415, "Magnetic Autocontrol GmbH"}
{0x002416, "Any Use"}
{0x002417, "Thomson Telecom Belgium"}
{0x002418, "Nextwave Semiconductor"}
{0x002419, "Private"}
{0x00241a, "Red Beetle"}
{0x00241b, "iWOW Communications Pte"}
{0x00241c, "FuGang Electronic (DG) Co."}
{0x00241d, "Giga-byte Technology Co."}
{0x00241e, "Nintendo Co."}
{0x00241f, "DCT-Delta GmbH"}
{0x002420, "NetUP"}
{0x002421, "Micro-star Int'l CO."}
{0x002422, "Knapp Logistik Automation GmbH"}
{0x002423, "AzureWave Technologies (Shanghai)"}
{0x002424, "Axis Network Technology"}
{0x002425, "Shenzhenshi chuangzhicheng Technology Co."}
{0x002426, "Nohmi Bosai"}
{0x002427, "SSI Computer"}
{0x002428, "EnergyICT"}
{0x002429, "MK Master"}
{0x00242a, "Hittite Microwave"}
{0x00242b, "Hon Hai Precision Ind.Co."}
{0x00242c, "Hon Hai Precision Ind. Co."}
{0x00242e, "Datastrip"}
{0x00242f, "VirtenSys"}
{0x002430, "Ruby Tech"}
{0x002431, "Uni-v co."}
{0x002432, "Neostar Technology Co."}
{0x002433, "Alps Electric Co."}
{0x002434, "Lectrosonics"}
{0x002435, "Wide"}
{0x002436, "Apple"}
{0x002437, "Motorola - BSG"}
{0x002438, "Brocade Communications Systems"}
{0x002439, "Essential Viewing Systems Limited"}
{0x00243a, "Ludl Electronic Products"}
{0x00243b, "Cssi (S) Pte"}
{0x00243c, "S.a.a.a."}
{0x00243d, "Emerson Appliance Motors and Controls"}
{0x00243f, "Storwize"}
{0x002440, "Halo Monitoring"}
{0x002441, "Wanzl Metallwarenfabrik GmbH"}
{0x002442, "Axona Limited"}
{0x002443, "Nortel Networks"}
{0x002444, "Nintendo Co."}
{0x002445, "LiquidxStream Systems"}
{0x002446, "MMB Research"}
{0x002447, "Kaztek Systems"}
{0x002448, "SpiderCloud Wireless"}
{0x002449, "Shen Zhen Lite Star Electronics Technology Co."}
{0x00244a, "Voyant International"}
{0x00244b, "Perceptron"}
{0x00244c, "Solartron Metrology"}
{0x00244d, "Hokkaido Electronics"}
{0x00244e, "RadChips"}
{0x00244f, "Asantron Technologies"}
{0x002450, "Cisco Systems"}
{0x002451, "Cisco Systems"}
{0x002452, "Silicon Software GmbH"}
{0x002453, "Initra d.o.o."}
{0x002454, "Samsung Electronics Co."}
{0x002455, "MuLogic BV"}
{0x002456, "2Wire"}
{0x002458, "PA Bastion CC"}
{0x002459, "ABB Stotz-kontakt Gmbh"}
{0x00245a, "Nanjing Panda Electronics Company Limited"}
{0x00245b, "Raidon Technology"}
{0x00245c, "Design-Com Technologies"}
{0x00245d, "Terberg besturingstechniek B.V."}
{0x00245e, "Hivision Co."}
{0x00245f, "Vine Telecom CO."}
{0x002460, "Giaval Science Development Co."}
{0x002461, "Shin Wang Tech."}
{0x002462, "Rayzone"}
{0x002463, "Phybridge"}
{0x002464, "Bridge Technologies Co AS"}
{0x002465, "Elentec"}
{0x002466, "Unitron nv"}
{0x002467, "AOC International (Europe) GmbH"}
{0x002468, "Sumavision Technologies Co."}
{0x002469, "Smart Doorphones"}
{0x00246a, "Solid Year Co."}
{0x00246b, "Covia"}
{0x00246c, "Aruba Networks"}
{0x00246d, "Weinzierl Engineering GmbH"}
{0x00246e, "Phihong USA"}
{0x00246f, "Onda Communication spa"}
{0x002470, "Aurotech Ultrasound AS."}
{0x002471, "Fusion MultiSystems dba Fusion-io"}
{0x002472, "ReDriven Power"}
{0x002473, "3Com Europe"}
{0x002474, "Autronica Fire And Securirty"}
{0x002475, "Compass System(Embedded Dept.)"}
{0x002476, "TAP.tv"}
{0x002477, "Tibbo Technology"}
{0x002478, "Mag Tech Electronics Co Limited"}
{0x002479, "Optec Displays"}
{0x00247a, "FU YI Cheng Technology Co."}
{0x00247b, "Actiontec Electronics"}
{0x00247c, "Nokia Danmark A/S"}
{0x00247d, "Nokia Danmark A/S"}
{0x00247e, "Universal Global Scientific Industrial Co."}
{0x00247f, "Nortel Networks"}
{0x002480, "Meteocontrol GmbH"}
{0x002481, "Hewlett-Packard Company"}
{0x002482, "Ruckus Wireless"}
{0x002483, "LG Electronics"}
{0x002484, "Bang and Olufsen Medicom a/s"}
{0x002485, "ConteXtream"}
{0x002486, "DesignArt Networks"}
{0x002487, "Blackboard"}
{0x002488, "Centre For Development Of Telematics"}
{0x002489, "Vodafone Omnitel N.V."}
{0x00248a, "Kaga Electronics Co."}
{0x00248b, "Hybus CO."}
{0x00248c, "Asustek Computer"}
{0x00248d, "Sony Computer Entertainment"}
{0x00248e, "Infoware ZRt."}
{0x00248f, "Do-monix"}
{0x002490, "Samsung Electronics Co."}
{0x002491, "Samsung Electronics"}
{0x002492, "Motorola, Broadband Solutions Group"}
{0x002493, "Motorola"}
{0x002494, "Shenzhen Baoxin Tech CO."}
{0x002495, "Motorola Mobility"}
{0x002496, "Ginzinger electronic systems"}
{0x002497, "Cisco Systems"}
{0x002498, "Cisco Systems"}
{0x002499, "Aquila Technologies"}
{0x00249a, "Beijing Zhongchuang Telecommunication Test Co."}
{0x00249b, "Action Star Enterprise Co."}
{0x00249c, "Bimeng Comunication System Co."}
{0x00249d, "NES Technology"}
{0x00249e, "ADC-Elektronik GmbH"}
{0x00249f, "RIM Testing Services"}
{0x0024a0, "Motorola Mobility"}
{0x0024a1, "Motorola Mobility"}
{0x0024a2, "Hong Kong Middleware Technology Limited"}
{0x0024a3, "Sonim Technologies"}
{0x0024a4, "Siklu Communication"}
{0x0024a5, "Buffalo"}
{0x0024a6, "Telestar Digital Gmbh"}
{0x0024a7, "Advanced Video Communications"}
{0x0024a8, "ProCurve Networking by HP"}
{0x0024a9, "Ag Leader Technology"}
{0x0024aa, "Dycor Technologies"}
{0x0024ab, "A7 Engineering"}
{0x0024ac, "Hangzhou DPtech Technologies Co."}
{0x0024ad, "Adolf Thies Gmbh & Co. KG"}
{0x0024ae, "Morpho"}
{0x0024af, "EchoStar Technologies"}
{0x0024b0, "Esab AB"}
{0x0024b1, "Coulomb Technologies"}
{0x0024b2, "Netgear"}
{0x0024b3, "Graf-Syteco GmbH & Co. KG"}
{0x0024b4, "Escatronic Gmbh"}
{0x0024b5, "Nortel Networks"}
{0x0024b6, "Seagate Technology"}
{0x0024b7, "GridPoint"}
{0x0024b8, "free alliance sdn bhd"}
{0x0024b9, "Wuhan Higheasy Electronic Technology DevelopmentLtd"}
{0x0024ba, "Texas Instruments"}
{0x0024bb, "Central"}
{0x0024bc, "HuRob Co."}
{0x0024bd, "Hainzl Industriesysteme GmbH"}
{0x0024be, "Sony"}
{0x0024bf, "Ciat"}
{0x0024c0, "NTI Comodo"}
{0x0024c1, "Motorola Mobility"}
{0x0024c2, "Asumo Co."}
{0x0024c3, "Cisco Systems"}
{0x0024c4, "Cisco Systems"}
{0x0024c5, "Meridian Audio Limited"}
{0x0024c6, "Hager Electro SAS"}
{0x0024c7, "Mobilarm"}
{0x0024c8, "Broadband Solutions Group"}
{0x0024c9, "Broadband Solutions Group"}
{0x0024ca, "Tobii Technology AB"}
{0x0024cb, "Autonet Mobile"}
{0x0024cc, "Fascinations Toys and Gifts"}
{0x0024cd, "Willow Garage"}
{0x0024ce, "Exeltech"}
{0x0024cf, "Inscape Data"}
{0x0024d0, "Shenzhen Sogood Industry Co."}
{0x0024d1, "Thomson"}
{0x0024d2, "Askey Computer"}
{0x0024d3, "Qualica"}
{0x0024d4, "Freebox SA"}
{0x0024d5, "Winward Industrial Limited"}
{0x0024d6, "Intel Corporate"}
{0x0024d7, "Intel Corporate"}
{0x0024d8, "IlSung Precision"}
{0x0024d9, "Bicom"}
{0x0024da, "Innovar Systems Limited"}
{0x0024db, "Alcohol Monitoring Systems"}
{0x0024dc, "Juniper Networks"}
{0x0024dd, "Centrak"}
{0x0024de, "Global Technology"}
{0x0024df, "Digitalbox Europe GmbH"}
{0x0024e0, "DS Tech"}
{0x0024e1, "Convey Computer"}
{0x0024e2, "Hasegawa Electric Co."}
{0x0024e3, "CAO Group"}
{0x0024e4, "Withings"}
{0x0024e5, "Seer Technology"}
{0x0024e6, "In Motion Technology"}
{0x0024e7, "Plaster Networks"}
{0x0024e8, "Dell"}
{0x0024e9, "Samsung Electronics Co.,, Storage System Division"}
{0x0024ea, "iris-GmbH infrared & intelligent sensors"}
{0x0024eb, "ClearPath Networks"}
{0x0024ec, "United Information Technology Co."}
{0x0024ed, "YT Elec. Co"}
{0x0024ee, "Wynmax"}
{0x0024ef, "Sony Ericsson Mobile Communications"}
{0x0024f0, "Seanodes"}
{0x0024f1, "Shenzhen Fanhai Sanjiang Electronics Co."}
{0x0024f2, "Uniphone Telecommunication Co."}
{0x0024f3, "Nintendo Co."}
{0x0024f4, "Kaminario Technologies"}
{0x0024f5, "NDS Surgical Imaging"}
{0x0024f6, "Miyoshi Electronics"}
{0x0024f7, "Cisco Systems"}
{0x0024f8, "Technical Solutions Company"}
{0x0024f9, "Cisco Systems"}
{0x0024fa, "Hilger u. Kern Gmbh"}
{0x0024fb, "Private"}
{0x0024fc, "QuoPin Co."}
{0x0024fd, "Prosilient Technologies AB"}
{0x0024fe, "AVM GmbH"}
{0x0024ff, "QLogic"}
{0x002500, "Apple"}
{0x002501, "JSC "Supertel""}
{0x002502, "NaturalPoint"}
{0x002503, "IBM"}
{0x002504, "Valiant Communications Limited"}
{0x002505, "eks Engel GmbH & Co. KG"}
{0x002506, "A.I. Antitaccheggio Italia SRL"}
{0x002507, "Astak"}
{0x002508, "Maquet Cardiopulmonary AG"}
{0x002509, "Sharetronic Group"}
{0x00250a, "Security Expert Co."}
{0x00250b, "Centrofactor "}
{0x00250c, "Enertrac"}
{0x00250d, "GZT Telkom-Telmor sp. z o.o."}
{0x00250e, "gt german telematics gmbh"}
{0x00250f, "On-Ramp Wireless"}
{0x002510, "Pico-Tesla Magnetic Therapies"}
{0x002511, "Elitegroup Computer System CO."}
{0x002512, "ZTE"}
{0x002513, "CXP Digital BV"}
{0x002514, "PC Worth Int'l Co."}
{0x002515, "SFR"}
{0x002516, "Integrated Design Tools"}
{0x002517, "Venntis"}
{0x002518, "Power Plus Communications AG"}
{0x002519, "Viaas"}
{0x00251a, "Psiber Data Systems"}
{0x00251b, "Philips CareServant"}
{0x00251c, "EDT"}
{0x00251d, "DSA Encore"}
{0x00251e, "Rotel Technologies"}
{0x00251f, "Zynus Vision"}
{0x002520, "SMA Railway Technology GmbH"}
{0x002521, "Logitek Electronic Systems"}
{0x002522, "ASRock Incorporation"}
{0x002523, "OCP"}
{0x002524, "Lightcomm Technology Co."}
{0x002525, "Ctera Networks"}
{0x002526, "Genuine Technologies Co."}
{0x002527, "Bitrode"}
{0x002528, "Daido Signal Co."}
{0x002529, "Comelit Group S.P.A"}
{0x00252a, "Chengdu GeeYa Technology Co."}
{0x00252b, "Stirling Energy Systems"}
{0x00252c, "Entourage Systems"}
{0x00252d, "Kiryung Electronics"}
{0x00252e, "Cisco Spvtg"}
{0x00252f, "Energy"}
{0x002530, "Aetas Systems"}
{0x002531, "Cloud Engines"}
{0x002532, "Digital Recorders"}
{0x002533, "Wittenstein AG"}
{0x002535, "Minimax GmbH & Co KG"}
{0x002536, "Oki Electric Industry Co."}
{0x002537, "Runcom Technologies"}
{0x002538, "Samsung Electronics Co.,, Memory Division"}
{0x002539, "IfTA GmbH"}
{0x00253a, "CEVA"}
{0x00253b, "din Dietmar Nocker Facilitymanagement GmbH"}
{0x00253c, "2Wire"}
{0x00253d, "DRS Consolidated Controls"}
{0x00253e, "Sensus Metering Systems"}
{0x002540, "Quasar Technologies"}
{0x002541, "Maquet Critical Care AB"}
{0x002542, "Pittasoft"}
{0x002543, "Moneytech"}
{0x002544, "LoJack"}
{0x002545, "Cisco Systems"}
{0x002546, "Cisco Systems"}
{0x002547, "Nokia Danmark A/S"}
{0x002548, "Nokia Danmark A/S"}
{0x002549, "Jeorich Tech. Co."}
{0x00254a, "RingCube Technologies"}
{0x00254b, "Apple"}
{0x00254c, "Videon Central"}
{0x00254d, "Singapore Technologies Electronics Limited"}
{0x00254e, "Vertex Wireless Co."}
{0x00254f, "Elettrolab Srl"}
{0x002550, "Riverbed Technology"}
{0x002551, "SE-Elektronic GmbH"}
{0x002552, "VXI"}
{0x002553, "ADB Broadband Italia"}
{0x002554, "Pixel8 Networks"}
{0x002555, "Visonic Technologies 1993"}
{0x002556, "Hon Hai Precision Ind. Co."}
{0x002557, "Research In Motion"}
{0x002558, "Mpedia"}
{0x002559, "Syphan Technologies"}
{0x00255a, "Tantalus Systems"}
{0x00255b, "CoachComm"}
{0x00255c, "NEC"}
{0x00255d, "Morningstar"}
{0x00255e, "Shanghai Dare Technologies Co."}
{0x00255f, "SenTec AG"}
{0x002560, "Ibridge Networks & Communications"}
{0x002561, "ProCurve Networking by HP"}
{0x002562, "interbro Co."}
{0x002563, "Luxtera"}
{0x002564, "Dell"}
{0x002565, "Vizimax"}
{0x002566, "Samsung Electronics Co."}
{0x002567, "Samsung Electronics"}
{0x002568, "Shenzhen Huawei Communication Technologies Co."}
{0x002569, "Sagem Communication"}
{0x00256a, "inIT - Institut Industrial IT"}
{0x00256b, "Atenix E.E. S.r.l."}
{0x00256c, ""Azimut" Production Association JSC"}
{0x00256d, "Broadband Forum"}
{0x00256e, "Van Breda B.V."}
{0x00256f, "Dantherm Power"}
{0x002570, "Eastern Communications Company Limited"}
{0x002571, "Zhejiang Tianle Digital Electric Co."}
{0x002572, "Nemo-Q International AB"}
{0x002573, "ST Electronics (Info-Security) Pte"}
{0x002574, "Kunimi Media Device Co."}
{0x002575, "FiberPlex"}
{0x002576, "Neli Technologies"}
{0x002577, "D-BOX Technologies"}
{0x002578, "JSC "Concern "Sozvezdie""}
{0x002579, "J & F Labs"}
{0x00257a, "Camco Produktions- und Vertriebs-gmbh Fr Beschallungs- und Beleuchtungsanlagen"}
{0x00257b, "STJ  Electronics  PVT "}
{0x00257c, "Huachentel Technology Development Co."}
{0x00257d, "PointRed Telecom Private"}
{0x00257e, "NEW POS Technology Limited"}
{0x00257f, "CallTechSolution Co."}
{0x002580, "Equipson S.A."}
{0x002581, "x-star networks"}
{0x002582, "Maksat Technologies (P)"}
{0x002583, "Cisco Systems"}
{0x002584, "Cisco Systems"}
{0x002585, "Kokuyo S&T Co."}
{0x002586, "Tp-link Technologies Co."}
{0x002587, "Vitality"}
{0x002588, "Genie Industries"}
{0x002589, "Hills Industries Limited"}
{0x00258a, "Pole/Zero"}
{0x00258b, "Mellanox Technologies"}
{0x00258c, "Esus Elektronik SAN. VE DIS. TIC. STI."}
{0x00258d, "Haier"}
{0x00258e, "The Weather Channel"}
{0x00258f, "Trident Microsystems"}
{0x002590, "Super Micro Computer"}
{0x002591, "Nextek"}
{0x002592, "Guangzhou Shirui Electronic Co."}
{0x002593, "DatNet Informatikai Kft."}
{0x002594, "Eurodesign BG"}
{0x002595, "Northwest Signal Supply"}
{0x002596, "Gigavision srl"}
{0x002597, "Kalki Communication Technologies"}
{0x002598, "Zhong Shan City Litai Electronic Industrial Co."}
{0x002599, "Hedon e.d. B.V."}
{0x00259a, "CEStronics GmbH"}
{0x00259b, "Beijing Pkunity Microsystems Technology Co."}
{0x00259c, "Cisco-Linksys"}
{0x00259d, "Private"}
{0x00259e, "Huawei Technologies Co."}
{0x00259f, "TechnoDigital Technologies GmbH"}
{0x0025a0, "Nintendo Co."}
{0x0025a1, "Enalasys"}
{0x0025a2, "Alta Definicion Linceo S.L."}
{0x0025a3, "Trimax Wireless"}
{0x0025a4, "EuroDesign embedded technologies GmbH"}
{0x0025a5, "Walnut Media Network"}
{0x0025a6, "Central Network Solution Co."}
{0x0025a7, "Comverge"}
{0x0025a8, "Kontron (BeiJing) Technology Co."}
{0x0025a9, "Shanghai Embedway Information Technologies Co."}
{0x0025aa, "Beijing Soul Technology Co."}
{0x0025ab, "AIO LCD PC BU / TPV"}
{0x0025ac, "I-Tech"}
{0x0025ad, "Manufacturing Resources International"}
{0x0025ae, "Microsoft"}
{0x0025af, "Comfile Technology"}
{0x0025b0, "Schmartz"}
{0x0025b1, "Maya-Creation"}
{0x0025b2, "LFK-Lenkflugkrpersysteme GmbH"}
{0x0025b3, "Hewlett-Packard Company"}
{0x0025b4, "Cisco Systems"}
{0x0025b5, "Cisco Systems"}
{0x0025b6, "Telecom FM"}
{0x0025b7, "Costar  electronics"}
{0x0025b8, "Agile Communications"}
{0x0025b9, "Agilink Systems"}
{0x0025ba, "Alcatel-Lucent IPD"}
{0x0025bb, "Innerint Co."}
{0x0025bc, "Apple"}
{0x0025bd, "Italdata Ingegneria dell'Idea S.p.A."}
{0x0025be, "Tektrap Systems"}
{0x0025bf, "Wireless Cables"}
{0x0025c0, "ZillionTV"}
{0x0025c1, "Nawoo Korea"}
{0x0025c2, "RingBell Co."}
{0x0025c3, "Nortel Networks"}
{0x0025c4, "Ruckus Wireless"}
{0x0025c5, "Star Link Communication Pvt."}
{0x0025c6, "kasercorp"}
{0x0025c7, "altek"}
{0x0025c8, "S-Access GmbH"}
{0x0025c9, "Shenzhen Huapu Digital CO."}
{0x0025ca, "LS Research"}
{0x0025cb, "Reiner SCT"}
{0x0025cc, "Mobile Communications Korea Incorporated"}
{0x0025cd, "Skylane Optics"}
{0x0025ce, "InnerSpace"}
{0x0025cf, "Nokia Danmark A/S"}
{0x0025d0, "Nokia Danmark A/S"}
{0x0025d1, "Eastech Electronics (Taiwan)"}
{0x0025d2, "InpegVision Co."}
{0x0025d3, "AzureWave Technologies"}
{0x0025d4, "Fortress Technologies"}
{0x0025d5, "Robonica (Pty)"}
{0x0025d6, "The Kroger Co."}
{0x0025d7, "Cedo"}
{0x0025d8, "Korea Maintenance"}
{0x0025d9, "DataFab Systems"}
{0x0025da, "Secura Key"}
{0x0025db, "ATI Electronics(Shenzhen) Co."}
{0x0025dc, "Sumitomo Electric Networks"}
{0x0025dd, "Sunnytek Information CO."}
{0x0025de, "Probits Co."}
{0x0025df, "Private"}
{0x0025e0, "CeedTec Sdn Bhd"}
{0x0025e1, "Shanghai Seeyoo Electronic & Technology CO."}
{0x0025e2, "Everspring Industry Co."}
{0x0025e3, "Hanshinit"}
{0x0025e4, "Omni-wifi"}
{0x0025e5, "LG Electronics"}
{0x0025e6, "Belgian Monitoring Systems bvba"}
{0x0025e7, "Sony Ericsson Mobile Communications"}
{0x0025e8, "Idaho Technology"}
{0x0025e9, "i-mate Development"}
{0x0025ea, "Iphion BV"}
{0x0025eb, "Reutech Radar Systems (PTY)"}
{0x0025ec, "Humanware"}
{0x0025ed, "NuVo Technologies"}
{0x0025ee, "Avtex"}
{0x0025ef, "I-TEC Co."}
{0x0025f0, "Suga Electronics Limited"}
{0x0025f1, "Motorola Mobility"}
{0x0025f2, "Motorola Mobility"}
{0x0025f3, "Nordwestdeutsche Zhlerrevision"}
{0x0025f4, "KoCo Connector AG"}
{0x0025f5, "DVS Korea, Co."}
{0x0025f6, "netTALK.com"}
{0x0025f7, "Ansaldo STS USA"}
{0x0025f9, "GMK electronic design GmbH"}
{0x0025fa, "J&M Analytik AG"}
{0x0025fb, "Tunstall Healthcare A/S"}
{0x0025fc, "Enda Endustriyel Elektronik STI."}
{0x0025fd, "OBR Centrum Techniki Morskiej S.A."}
{0x0025fe, "Pilot Electronics"}
{0x0025ff, "CreNova Technology GmbH"}
{0x002600, "Teac Australia"}
{0x002601, "Cutera"}
{0x002602, "Smart Temps"}
{0x002603, "Shenzhen Wistar Technology Co."}
{0x002604, "Audio Processing Technology"}
{0x002605, "CC Systems AB"}
{0x002606, "Raumfeld Gmbh"}
{0x002607, "Enabling Technology"}
{0x002608, "Apple"}
{0x002609, "Phyllis Co."}
{0x00260a, "Cisco Systems"}
{0x00260b, "Cisco Systems"}
{0x00260c, "Dataram"}
{0x00260d, "Micronetics"}
{0x00260e, "Ablaze Systems"}
{0x00260f, "Linn Products"}
{0x002610, "Apacewave Technologies"}
{0x002611, "Licera AB"}
{0x002612, "Space Exploration Technologies"}
{0x002613, "Engel Axil S.L."}
{0x002614, "Ktnf"}
{0x002615, "Teracom Limited"}
{0x002616, "Rosemount"}
{0x002617, "OEM Worldwide"}
{0x002618, "Asustek Computer"}
{0x002619, "FRC"}
{0x00261a, "Femtocomm System Technology"}
{0x00261b, "Laurel Bank Machines CO."}
{0x00261c, "Neovia"}
{0x00261d, "COP Security System"}
{0x00261e, "Qingbang Elec(sz) CO."}
{0x00261f, "SAE Magnetics (H.K.)"}
{0x002620, "Isgus Gmbh"}
{0x002621, "InteliCloud Technology"}
{0x002622, "Compal Information (kunshan) CO."}
{0x002623, "JRD Communication"}
{0x002624, "Thomson"}
{0x002625, "MediaSputnik"}
{0x002626, "Geophysical Survey Systems"}
{0x002627, "Truesell"}
{0x002628, "companytec automao e controle ltda"}
{0x002629, "Juphoon System Software"}
{0x00262a, "Proxense"}
{0x00262b, "Wongs Electronics Co."}
{0x00262c, "IKT Advanced Technologies s.r.o."}
{0x00262d, "Wistron"}
{0x00262e, "Chengdu Jiuzhou Electronic Technology"}
{0x00262f, "Hamamatsu TOA Electronics"}
{0x002630, "AcorelS"}
{0x002631, "Commtact"}
{0x002632, "Instrumentation Technologies d.d."}
{0x002633, "MIR - Medical International Research"}
{0x002634, "Infineta Systems"}
{0x002635, "Bluetechnix GmbH"}
{0x002636, "Motorola Mobility"}
{0x002637, "Samsung Electro-Mechanics"}
{0x002638, "Xia Men Joyatech Co."}
{0x002639, "T.M. Electronics"}
{0x00263a, "Digitec Systems"}
{0x00263b, "Onbnetech"}
{0x00263c, "Bachmann GmbH & Co. KG"}
{0x00263d, "MIA"}
{0x00263e, "Trapeze Networks"}
{0x00263f, "Lios Technology Gmbh"}
{0x002640, "Baustem Broadband Technologies"}
{0x002641, "Motorola"}
{0x002642, "Motorola"}
{0x002643, "Alps Electric Co."}
{0x002644, "Thomson Telecom Belgium"}
{0x002645, "Circontrol S.A."}
{0x002646, "Shenyang Tongfang Multimedia Technology Company Limited"}
{0x002647, "WFE Technology"}
{0x002648, "Emitech"}
{0x00264a, "Apple"}
{0x00264c, "Shanghai DigiVision Technology Co."}
{0x00264d, "Arcadyan Technology"}
{0x00264e, "Rail & Road Protec GmbH"}
{0x00264f, "Krger&Gothe GmbH"}
{0x002650, "2Wire"}
{0x002651, "Cisco Systems"}
{0x002652, "Cisco Systems"}
{0x002653, "DaySequerra"}
{0x002654, "3Com"}
{0x002655, "Hewlett-Packard Company"}
{0x002656, "Sansonic Electronics USA"}
{0x002657, "OOO NPP Ekra"}
{0x002658, "T-Platforms (Cyprus) Limited"}
{0x002659, "Nintendo Co."}
{0x00265a, "D-Link"}
{0x00265b, "Hitron Technologies."}
{0x00265c, "Hon Hai Precision Ind. Co."}
{0x00265d, "Samsung Electronics"}
{0x00265e, "Hon Hai Precision Ind. Co."}
{0x00265f, "Samsung Electronics Co."}
{0x002660, "Logiways"}
{0x002661, "Irumtek Co."}
{0x002662, "Actiontec Electronics"}
{0x002663, "Shenzhen Huitaiwei Tech."}
{0x002664, "Core System Japan"}
{0x002665, "ProtectedLogic"}
{0x002666, "EFM Networks"}
{0x002667, "Carecom Co."}
{0x002668, "Nokia Danmark A/S"}
{0x002669, "Nokia Danmark A/S"}
{0x00266a, "Essensium NV"}
{0x00266b, "Shine Union Enterprise Limited"}
{0x00266c, "Inventec"}
{0x00266d, "MobileAccess Networks"}
{0x00266e, "Nissho-denki Co."}
{0x00266f, "Coordiwise Technology"}
{0x002670, "Cinch Connectors"}
{0x002671, "Autovision Co."}
{0x002672, "Aamp of America"}
{0x002673, "Ricoh Company"}
{0x002674, "Electronic Solutions"}
{0x002675, "Aztech Electronics Pte"}
{0x002676, "Commidt AS"}
{0x002677, "Deif A/S"}
{0x002678, "Logic Instrument SA"}
{0x002679, "Euphonic Technologies"}
{0x00267a, "wuhan hongxin telecommunication technologies co."}
{0x00267b, "GSI Helmholtzzentrum fr Schwerionenforschung GmbH"}
{0x00267c, "Metz-Werke GmbH & Co KG"}
{0x00267d, "A-Max Technology Macao Commercial Offshore Company Limited"}
{0x00267e, "Parrot SA"}
{0x00267f, "Zenterio AB"}
{0x002680, "Lockie Innovation"}
{0x002681, "Interspiro AB"}
{0x002682, "Gemtek Technology Co."}
{0x002683, "Ajoho Enterprise Co."}
{0x002684, "Kisan System"}
{0x002685, "Digital Innovation"}
{0x002686, "Quantenna Communcations"}
{0x002687, "Allied Telesis, K.K Corega Division."}
{0x002688, "Juniper Networks"}
{0x002689, "General Dynamics Robotic Systems"}
{0x00268a, "Terrier SC"}
{0x00268b, "Guangzhou Escene Computer Technology Limited"}
{0x00268c, "StarLeaf"}
{0x00268d, "CellTel S.p.A."}
{0x00268e, "Alta Solutions"}
{0x00268f, "MTA SpA"}
{0x002690, "I DO IT"}
{0x002691, "Sagem Communication"}
{0x002692, "Mitsubishi Electric Co."}
{0x002693, "QVidium Technologies"}
{0x002694, "Senscient"}
{0x002695, "ZT Group Int'l"}
{0x002696, "Noolix Co."}
{0x002697, "Cheetah Technologies"}
{0x002698, "Cisco Systems"}
{0x002699, "Cisco Systems"}
{0x00269a, "carina system co."}
{0x00269b, "Sokrat"}
{0x00269c, "Itus Japan CO."}
{0x00269d, "M2Mnet Co."}
{0x00269e, "Quanta Computer"}
{0x00269f, "Private"}
{0x0026a0, "moblic"}
{0x0026a1, "Megger"}
{0x0026a2, "Instrumentation Technology Systems"}
{0x0026a3, "FQ Ingenieria Electronica S.A."}
{0x0026a4, "Novus Produtos Eletronicos Ltda"}
{0x0026a5, "Microrobot.co."}
{0x0026a6, "Trixell"}
{0x0026a7, "Connect SRL"}
{0x0026a8, "Daehap Hyper-tech"}
{0x0026a9, "Strong Technologies"}
{0x0026aa, "Kenmec Mechanical Engineering Co."}
{0x0026ab, "Seiko Epson"}
{0x0026ac, "Shanghai Luster Teraband Photonic Co."}
{0x0026ad, "Arada Systems"}
{0x0026ae, "Wireless Measurement"}
{0x0026af, "Duelco A/S"}
{0x0026b0, "Apple"}
{0x0026b1, "Navis Auto Motive Systems"}
{0x0026b2, "Setrix AG"}
{0x0026b3, "Thales Communications"}
{0x0026b4, "Ford Motor Company"}
{0x0026b5, "Icomm Tele"}
{0x0026b6, "Askey Computer"}
{0x0026b7, "Kingston Technology Company"}
{0x0026b8, "Actiontec Electronics"}
{0x0026b9, "Dell"}
{0x0026ba, "Motorola Mobility"}
{0x0026bb, "Apple"}
{0x0026bc, "General Jack Technology"}
{0x0026bd, "Jtec Card & Communication Co."}
{0x0026be, "Schoonderbeek Elektronica Systemen B.V."}
{0x0026bf, "ShenZhen Temobi Science&Tech Development Co."}
{0x0026c0, "EnergyHub"}
{0x0026c1, "Artray CO."}
{0x0026c2, "Scdi Co."}
{0x0026c3, "Insightek"}
{0x0026c4, "Cadmos microsystems S.r.l."}
{0x0026c5, "Guangdong Gosun Telecommunications Co."}
{0x0026c6, "Intel Corporate"}
{0x0026c7, "Intel Corporate"}
{0x0026c8, "System Sensor"}
{0x0026c9, "Proventix Systems"}
{0x0026ca, "Cisco Systems"}
{0x0026cb, "Cisco Systems"}
{0x0026cc, "Nokia Danmark A/S"}
{0x0026cd, "PurpleComm"}
{0x0026ce, "Kozumi USA"}
{0x0026cf, "Deka R&D"}
{0x0026d0, "Semihalf"}
{0x0026d1, "S Squared Innovations"}
{0x0026d2, "Pcube Systems"}
{0x0026d3, "Zeno Information System"}
{0x0026d4, "Irca SpA"}
{0x0026d5, "Ory Solucoes em Comercio de Informatica Ltda."}
{0x0026d6, "Ningbo Andy Optoelectronic Co."}
{0x0026d7, "Xiamen BB Electron & Technology Co."}
{0x0026d8, "Magic Point"}
{0x0026d9, "Pace plc"}
{0x0026da, "Universal Media /Slovakia/ s.r.o."}
{0x0026db, "Ionics EMS"}
{0x0026dc, "Optical Systems Design"}
{0x0026dd, "Fival"}
{0x0026de, "FDI Matelec"}
{0x0026df, "TaiDoc Technology"}
{0x0026e0, "Asiteq"}
{0x0026e1, "Stanford University, OpenFlow Group"}
{0x0026e2, "LG Electronics"}
{0x0026e3, "DTI"}
{0x0026e4, "Canal Overseas"}
{0x0026e5, "AEG Power Solutions"}
{0x0026e6, "Visionhitech Co."}
{0x0026e7, "Shanghai Onlan Communication Tech. Co."}
{0x0026e8, "Murata Manufacturing Co."}
{0x0026e9, "SP"}
{0x0026ea, "Cheerchip Electronic Technology (ShangHai) Co."}
{0x0026eb, "Advanced Spectrum Technology Co."}
{0x0026ec, "Legrand Home Systems"}
{0x0026ed, "zte"}
{0x0026ee, "TKM GmbH"}
{0x0026ef, "Technology Advancement Group"}
{0x0026f0, "cTrixs International GmbH."}
{0x0026f1, "ProCurve Networking by HP"}
{0x0026f2, "Netgear"}
{0x0026f3, "SMC Networks"}
{0x0026f4, "Nesslab"}
{0x0026f5, "Xrplus"}
{0x0026f6, "Military Communication Institute"}
{0x0026f7, "Infosys Technologies"}
{0x0026f8, "Golden Highway Industry Development Co."}
{0x0026f9, "S.E.M. srl"}
{0x0026fa, "BandRich"}
{0x0026fb, "AirDio Wireless"}
{0x0026fc, "AcSiP Technology"}
{0x0026fd, "Interactive Intelligence"}
{0x0026fe, "MKD Technology"}
{0x0026ff, "Research In Motion"}
{0x002700, "Shenzhen Siglent Technology Co."}
{0x002701, "Incostartec Gmbh"}
{0x002702, "SolarEdge Technologies"}
{0x002703, "Testech Electronics Pte"}
{0x002704, "Accelerated Concepts"}
{0x002705, "Sectronic"}
{0x002706, "Yoisys"}
{0x002707, "Lift Complex DS"}
{0x002708, "Nordiag ASA"}
{0x002709, "Nintendo Co."}
{0x00270a, "IEE S.A."}
{0x00270b, "Adura Technologies"}
{0x00270c, "Cisco Systems"}
{0x00270d, "Cisco Systems"}
{0x00270e, "Intel Corporate"}
{0x00270f, "Envisionnovation"}
{0x002710, "Intel Corporate"}
{0x002711, "LanPro"}
{0x002712, "MaxVision"}
{0x002713, "Universal Global Scientific Industrial Co."}
{0x002714, "Grainmustards, Co"}
{0x002715, "Rebound Telecom. Co."}
{0x002716, "Adachi-Syokai Co."}
{0x002717, "CE Digital(Zhenjiang)Co."}
{0x002718, "Suzhou NEW Seaunion Video Technology Co."}
{0x002719, "Tp-link Technologies CO."}
{0x00271a, "Geenovo Technology"}
{0x00271b, "Alec Sicherheitssysteme GmbH"}
{0x00271c, "Mercury"}
{0x00271d, "Comba Telecom Systems (China)"}
{0x00271e, "Xagyl Communications"}
{0x00271f, "Mipro Electronics Co."}
{0x002720, "New-sol COM"}
{0x002721, "Shenzhen Baoan Fenda Industrial Co."}
{0x002722, "Ubiquiti Networks"}
{0x0027f8, "Brocade Communications Systems"}
{0x002a6a, "Cisco Systems"}
{0x002aaf, "LARsys-Automation GmbH"}
{0x002d76, "Titech Gmbh"}
{0x003000, "Allwell Technology"}
{0x003001, "SMP"}
{0x003002, "Expand Networks"}
{0x003003, "Phasys"}
{0x003004, "Leadtek Research"}
{0x003005, "Fujitsu Siemens Computers"}
{0x003006, "Superpower Computer"}
{0x003007, "OPTI"}
{0x003008, "Avio Digital"}
{0x003009, "Tachion Networks"}
{0x00300a, "Aztech Electronics Pte"}
{0x00300b, "mPHASE Technologies"}
{0x00300c, "Congruency"}
{0x00300d, "MMC Technology"}
{0x00300e, "Klotz Digital AG"}
{0x00300f, "IMT - Information Management"}
{0x003010, "Visionetics International"}
{0x003011, "HMS Industrial Networks"}
{0x003012, "Digital Engineering"}
{0x003013, "NEC"}
{0x003014, "Divio"}
{0x003015, "CP Clare"}
{0x003016, "Ishida CO."}
{0x003017, "BlueArc UK"}
{0x003018, "Jetway Information Co."}
{0x003019, "Cisco Systems"}
{0x00301a, "Smartbridges PTE."}
{0x00301b, "Shuttle"}
{0x00301c, "Altvater Airdata Systems"}
{0x00301d, "Skystream"}
{0x00301e, "3COM Europe"}
{0x00301f, "Optical Networks"}
{0x003020, "TSI"}
{0x003021, "Hsing TECH. Enterprise Co."}
{0x003022, "Fong Kai Industrial Co."}
{0x003023, "Cogent Computer Systems"}
{0x003024, "Cisco Systems"}
{0x003025, "Checkout Computer Systems"}
{0x003026, "HeiTel Digital Video GmbH"}
{0x003027, "Kerbango"}
{0x003028, "Fase Saldatura srl"}
{0x003029, "Opicom"}
{0x00302a, "Southern Information"}
{0x00302b, "Inalp Networks"}
{0x00302c, "Sylantro Systems"}
{0x00302d, "Quantum Bridge Communications"}
{0x00302e, "Hoft & Wessel AG"}
{0x00302f, "GE Aviation System"}
{0x003030, "Harmonix"}
{0x003031, "Lightwave Communications"}
{0x003032, "MagicRam"}
{0x003033, "Orient Telecom CO."}
{0x003034, "SET Engineering"}
{0x003035, "Corning Incorporated"}
{0x003036, "RMP Elektroniksysteme Gmbh"}
{0x003037, "Packard Bell Nec Services"}
{0x003038, "XCP"}
{0x003039, "Softbook Press"}
{0x00303a, "Maatel"}
{0x00303b, "PowerCom Technology"}
{0x00303c, "Onnto"}
{0x00303d, "IVA"}
{0x00303e, "Radcom"}
{0x00303f, "TurboComm Tech"}
{0x003040, "Cisco Systems"}
{0x003041, "Saejin T & M CO."}
{0x003042, "DeTeWe-Deutsche Telephonwerke"}
{0x003043, "Idream Technologies, PTE."}
{0x003044, "CradlePoint"}
{0x003045, "Village Networks, (VNI)"}
{0x003046, "Controlled Electronic Manageme"}
{0x003047, "Nissei Electric CO."}
{0x003048, "Supermicro Computer"}
{0x003049, "Bryant Technology"}
{0x00304a, "Fraunhofer Ipms"}
{0x00304b, "Orbacom Systems"}
{0x00304c, "Appian Communications"}
{0x00304d, "ESI"}
{0x00304e, "Bustec Production"}
{0x00304f, "Planet Technology"}
{0x003050, "Versa Technology"}
{0x003051, "Orbit Avionic & Communication"}
{0x003052, "Elastic Networks"}
{0x003053, "Basler AG"}
{0x003054, "Castlenet Technology"}
{0x003055, "Renesas Technology America"}
{0x003056, "Beck IPC GmbH"}
{0x003057, "QTelNet"}
{0x003058, "API Motion"}
{0x003059, "Kontron Compact Computers AG"}
{0x00305a, "Telgen"}
{0x00305b, "Toko"}
{0x00305c, "Smar Laboratories"}
{0x00305d, "Digitra Systems"}
{0x00305e, "Abelko Innovation"}
{0x00305f, "Hasselblad"}
{0x003060, "Powerfile"}
{0x003061, "MobyTEL"}
{0x003062, "Path 1 Network Technol's"}
{0x003063, "Santera Systems"}
{0x003064, "Adlink Technology"}
{0x003065, "Apple Computer"}
{0x003066, "RFM"}
{0x003067, "Biostar Microtech Int'l"}
{0x003068, "Cybernetics TECH. CO."}
{0x003069, "Impacct Technology"}
{0x00306a, "Penta Media CO."}
{0x00306b, "Cmos Systems"}
{0x00306c, "Hitex Holding GmbH"}
{0x00306d, "Lucent Technologies"}
{0x00306e, "Hewlett Packard"}
{0x00306f, "Seyeon TECH. CO."}
{0x003070, "1Net"}
{0x003071, "Cisco Systems"}
{0x003072, "Intellibyte"}
{0x003073, "International Microsystems"}
{0x003074, "Equiinet"}
{0x003075, "Adtech"}
{0x003076, "Akamba"}
{0x003077, "Onprem Networks"}
{0x003078, "Cisco Systems"}
{0x003079, "CQOS"}
{0x00307a, "Advanced Technology & Systems"}
{0x00307b, "Cisco Systems"}
{0x00307c, "Adid SA"}
{0x00307d, "GRE America"}
{0x00307e, "Redflex Communication Systems"}
{0x00307f, "Irlan"}
{0x003080, "Cisco Systems"}
{0x003081, "Altos C&C"}
{0x003082, "Taihan Electric Wire CO."}
{0x003083, "Ivron Systems"}
{0x003084, "Allied Telesyn Internaional"}
{0x003085, "Cisco Systems"}
{0x003086, "Transistor Devices"}
{0x003087, "Vega Grieshaber KG"}
{0x003088, "Ericsson"}
{0x003089, "Spectrapoint Wireless"}
{0x00308a, "Nicotra Sistemi S.P.A"}
{0x00308b, "Brix Networks"}
{0x00308c, "Quantum"}
{0x00308d, "Pinnacle Systems"}
{0x00308e, "Cross Match Technologies"}
{0x00308f, "Micrilor"}
{0x003090, "Cyra Technologies"}
{0x003091, "Taiwan First Line ELEC."}
{0x003092, "ModuNORM GmbH"}
{0x003093, "Sonnet Technologies"}
{0x003094, "Cisco Systems"}
{0x003095, "Procomp Informatics"}
{0x003096, "Cisco Systems"}
{0x003097, "AB Regin"}
{0x003098, "Global Converging Technologies"}
{0x003099, "Boenig UND Kallenbach OHG"}
{0x00309a, "Astro Terra"}
{0x00309b, "Smartware"}
{0x00309c, "Timing Applications"}
{0x00309d, "Nimble Microsystems"}
{0x00309e, "Workbit"}
{0x00309f, "Amber Networks"}
{0x0030a0, "Tyco Submarine Systems"}
{0x0030a1, "Webgate"}
{0x0030a2, "Lightner Engineering"}
{0x0030a3, "Cisco Systems"}
{0x0030a4, "Woodwind Communications System"}
{0x0030a5, "Active Power"}
{0x0030a6, "Vianet Technologies"}
{0x0030a7, "Schweitzer Engineering"}
{0x0030a8, "Ol'e Communications"}
{0x0030a9, "Netiverse"}
{0x0030aa, "Axus Microsystems"}
{0x0030ab, "Delta Networks"}
{0x0030ac, "Systeme Lauer GmbH & Co."}
{0x0030ad, "Shanghai Communication"}
{0x0030ae, "Times N System"}
{0x0030af, "Honeywell GmbH"}
{0x0030b0, "Convergenet Technologies"}
{0x0030b1, "TrunkNet"}
{0x0030b2, "L-3 Sonoma EO"}
{0x0030b3, "San Valley Systems"}
{0x0030b4, "Intersil"}
{0x0030b5, "Tadiran Microwave Networks"}
{0x0030b6, "Cisco Systems"}
{0x0030b7, "Teletrol Systems"}
{0x0030b8, "RiverDelta Networks"}
{0x0030b9, "Ectel"}
{0x0030ba, "Ac&t System CO."}
{0x0030bb, "CacheFlow"}
{0x0030bc, "Optronic AG"}
{0x0030bd, "Belkin Components"}
{0x0030be, "City-Net Technology"}
{0x0030bf, "Multidata Gmbh"}
{0x0030c0, "Lara Technology"}
{0x0030c1, "Hewlett-packard"}
{0x0030c2, "Comone"}
{0x0030c3, "Flueckiger Elektronik AG"}
{0x0030c4, "Canon Imaging Systems"}
{0x0030c5, "Cadence Design Systems"}
{0x0030c6, "Control Solutions"}
{0x0030c7, "Macromate"}
{0x0030c8, "GAD LINE"}
{0x0030c9, "LuxN"}
{0x0030ca, "Discovery Com"}
{0x0030cb, "Omni Flow Computers"}
{0x0030cc, "Tenor Networks"}
{0x0030cd, "Conexant Systems"}
{0x0030ce, "Zaffire"}
{0x0030cf, "TWO Technologies"}
{0x0030d0, "Tellabs"}
{0x0030d1, "Inova"}
{0x0030d2, "WIN Technologies, CO."}
{0x0030d3, "Agilent Technologies"}
{0x0030d4, "AAE Systems"}
{0x0030d5, "DResearch GmbH"}
{0x0030d6, "MSC Vertriebs Gmbh"}
{0x0030d7, "Innovative Systems, L.L.C."}
{0x0030d8, "Sitek"}
{0x0030d9, "Datacore Software"}
{0x0030da, "Comtrend CO."}
{0x0030db, "Mindready Solutions"}
{0x0030dc, "Rightech"}
{0x0030dd, "Indigita"}
{0x0030de, "Wago Kontakttechnik Gmbh"}
{0x0030df, "Kb/tel Telecomunicaciones"}
{0x0030e0, "Oxford Semiconductor"}
{0x0030e1, "Network Equipment Technologies"}
{0x0030e2, "Garnet Systems CO."}
{0x0030e3, "Sedona Networks"}
{0x0030e4, "Chiyoda System Riken"}
{0x0030e5, "Amper Datos S.A."}
{0x0030e6, "Draeger Medical Systems"}
{0x0030e7, "CNF Mobile Solutions"}
{0x0030e8, "Ensim"}
{0x0030e9, "GMA Communication Manufact'g"}
{0x0030ea, "TeraForce Technology"}
{0x0030eb, "Turbonet Communications"}
{0x0030ec, "Borgardt"}
{0x0030ed, "Expert Magnetics"}
{0x0030ee, "DSG Technology"}
{0x0030ef, "Neon Technology"}
{0x0030f0, "Uniform Industrial"}
{0x0030f1, "Accton Technology"}
{0x0030f2, "Cisco Systems"}
{0x0030f3, "At Work Computers"}
{0x0030f4, "Stardot Technologies"}
{0x0030f5, "Wild Lab."}
{0x0030f6, "Securelogix"}
{0x0030f7, "Ramix"}
{0x0030f8, "Dynapro Systems"}
{0x0030f9, "Sollae Systems Co."}
{0x0030fa, "Telica"}
{0x0030fb, "AZS Technology AG"}
{0x0030fc, "Terawave Communications"}
{0x0030fd, "Integrated Systems Design"}
{0x0030fe, "DSA GmbH"}
{0x0030ff, "Datafab Systems"}
{0x00336c, "SynapSense"}
{0x0034f1, "Radicom Research"}
{0x003532, "Electro-Metrics"}
{0x0036f8, "Conti Temic microelectronic GmbH"}
{0x00376d, "Murata Manufacturing Co."}
{0x003a98, "Cisco Systems"}
{0x003a99, "Cisco Systems"}
{0x003a9a, "Cisco Systems"}
{0x003a9b, "Cisco Systems"}
{0x003a9c, "Cisco Systems"}
{0x003a9d, "NEC AccessTechnica"}
{0x003aaf, "BlueBit"}
{0x003cc5, "Wonwoo Engineering Co."}
{0x003d41, "Hatteland Computer AS"}
{0x003ee1, "Apple"}
{0x004000, "PCI Componentes DA Amzonia"}
{0x004001, "Zero One Technology Co."}
{0x004002, "Perle Systems Limited"}
{0x004003, "Emerson Process Management Power & Water Solutions"}
{0x004004, "ICM CO."}
{0x004005, "ANI Communications"}
{0x004006, "Sampo Technology"}
{0x004007, "Telmat Informatique"}
{0x004008, "A Plus Info"}
{0x004009, "Tachibana Tectron CO."}
{0x00400a, "Pivotal Technologies"}
{0x00400b, "Cisco Systems"}
{0x00400c, "General Micro Systems"}
{0x00400d, "Lannet Data Communications"}
{0x00400e, "Memotec"}
{0x00400f, "Datacom Technologies"}
{0x004010, "Sonic Systems"}
{0x004011, "Andover Controls"}
{0x004012, "Windata"}
{0x004013, "NTT Data COMM. Systems"}
{0x004014, "Comsoft Gmbh"}
{0x004015, "Ascom Infrasys AG"}
{0x004016, "ADC - Global Connectivity Solutions Division"}
{0x004017, "Silex Technology America"}
{0x004018, "Adobe Systems"}
{0x004019, "Aeon Systems"}
{0x00401a, "Fuji Electric CO."}
{0x00401b, "Printer Systems"}
{0x00401c, "AST Research"}
{0x00401d, "Invisible Software"}
{0x00401e, "ICC"}
{0x00401f, "Colorgraph"}
{0x004020, "TE Connectivity"}
{0x004021, "Raster Graphics"}
{0x004022, "Klever Computers"}
{0x004023, "Logic"}
{0x004024, "Compac"}
{0x004025, "Molecular Dynamics"}
{0x004026, "Buffalo"}
{0x004027, "SMC Massachusetts"}
{0x004028, "Netcomm Limited"}
{0x004029, "Compex"}
{0x00402a, "Canoga-perkins"}
{0x00402b, "Trigem Computer"}
{0x00402c, "Isis Distributed Systems"}
{0x00402d, "Harris Adacom"}
{0x00402e, "Precision Software"}
{0x00402f, "Xlnt Designs"}
{0x004030, "GK Computer"}
{0x004031, "Kokusai Electric CO."}
{0x004032, "Digital Communications"}
{0x004033, "Addtron Technology CO."}
{0x004034, "Bustek"}
{0x004035, "Opcom"}
{0x004036, "Tribe Computer Works"}
{0x004037, "Sea-ilan"}
{0x004038, "Talent Electric Incorporated"}
{0x004039, "Optec Daiichi Denko CO."}
{0x00403a, "Impact Technologies"}
{0x00403b, "Synerjet International"}
{0x00403c, "Forks"}
{0x00403d, "Teradata"}
{0x00403e, "Raster OPS"}
{0x00403f, "Ssangyong Computer Systems"}
{0x004040, "Ring Access"}
{0x004041, "Fujikura"}
{0x004042, "N.a.t. Gmbh"}
{0x004043, "Nokia Siemens Networks GmbH & Co. KG."}
{0x004044, "Qnix Computer CO."}
{0x004045, "Twinhead"}
{0x004046, "UDC Research Limited"}
{0x004047, "Wind River Systems"}
{0x004048, "SMD Informatica S.A."}
{0x004049, "Roche Diagnostics"}
{0x00404a, "West Australian Department"}
{0x00404b, "Maple Computer Systems"}
{0x00404c, "Hypertec"}
{0x00404d, "Telecommunications Techniques"}
{0x00404e, "Fluent"}
{0x00404f, "Space & Naval Warfare Systems"}
{0x004050, "Ironics, Incorporated"}
{0x004051, "Gracilis"}
{0x004052, "Star Technologies"}
{0x004053, "Ampro Computers"}
{0x004054, "Connection Machines Services"}
{0x004055, "Metronix Gmbh"}
{0x004056, "MCM Japan"}
{0x004057, "Lockheed - Sanders"}
{0x004058, "Kronos"}
{0x004059, "Yoshida Kogyo K. K."}
{0x00405a, "Goldstar Information & COMM."}
{0x00405b, "Funasset Limited"}
{0x00405c, "Future Systems"}
{0x00405d, "Star-tek"}
{0x00405e, "North Hills Israel"}
{0x00405f, "AFE Computers"}
{0x004060, "Comendec"}
{0x004061, "Datatech Enterprises CO."}
{0x004062, "E-systems,/garland DIV."}
{0x004063, "VIA Technologies"}
{0x004064, "KLA Instruments"}
{0x004065, "GTE Spacenet"}
{0x004066, "Hitachi Cable"}
{0x004067, "Omnibyte"}
{0x004068, "Extended Systems"}
{0x004069, "Lemcom Systems"}
{0x00406a, "Kentek Information Systems"}
{0x00406b, "Sysgen"}
{0x00406c, "Copernique"}
{0x00406d, "Lanco"}
{0x00406e, "Corollary"}
{0x00406f, "Sync Research"}
{0x004070, "Interware CO."}
{0x004071, "ATM Computer Gmbh"}
{0x004072, "Applied Innovation"}
{0x004073, "Bass Associates"}
{0x004074, "Cable AND Wireless"}
{0x004075, "M-trade (uk)"}
{0x004076, "Sun Conversion Technologies"}
{0x004077, "Maxton Technology"}
{0x004078, "Wearnes Automation PTE"}
{0x004079, "Juko Manufacture Company"}
{0x00407a, "Societe D'exploitation DU Cnit"}
{0x00407b, "Scientific Atlanta"}
{0x00407c, "Qume"}
{0x00407d, "Extension Technology"}
{0x00407e, "Evergreen Systems"}
{0x00407f, "Flir Systems"}
{0x004080, "Athenix"}
{0x004081, "Mannesmann Scangraphic Gmbh"}
{0x004082, "Laboratory Equipment"}
{0x004083, "TDA Industria DE Produtos"}
{0x004084, "Honeywell ACS"}
{0x004085, "Saab Instruments AB"}
{0x004086, "Michels & Kleberhoff Computer"}
{0x004087, "Ubitrex"}
{0x004088, "Mobius Technologies"}
{0x004089, "Meidensha"}
{0x00408a, "TPS Teleprocessing SYS. Gmbh"}
{0x00408b, "Raylan"}
{0x00408c, "Axis Communications AB"}
{0x00408d, "THE Goodyear Tire & Rubber CO."}
{0x00408e, "Digilog"}
{0x00408f, "Wm-data Minfo AB"}
{0x004090, "Ansel Communications"}
{0x004091, "Procomp Industria Eletronica"}
{0x004092, "ASP Computer Products"}
{0x004093, "Paxdata Networks"}
{0x004094, "Shographics"}
{0x004095, "R.p.t. Intergroups Int'l"}
{0x004096, "Cisco Systems"}
{0x004097, "Datex Division OF"}
{0x004098, "Dressler Gmbh & CO."}
{0x004099, "Newgen Systems"}
{0x00409a, "Network Express"}
{0x00409b, "HAL Computer Systems"}
{0x00409c, "Transware"}
{0x00409d, "Digiboard"}
{0x00409e, "Concurrent Technologies "}
{0x00409f, "Telco Systems"}
{0x0040a0, "Goldstar CO."}
{0x0040a1, "Ergo Computing"}
{0x0040a2, "Kingstar Technology"}
{0x0040a3, "Microunity Systems Engineering"}
{0x0040a4, "Rose Electronics"}
{0x0040a5, "Clinicomp INTL."}
{0x0040a6, "Cray"}
{0x0040a7, "Itautec Philco S.A."}
{0x0040a8, "IMF International"}
{0x0040a9, "Datacom"}
{0x0040aa, "Valmet Automation"}
{0x0040ab, "Roland DG"}
{0x0040ac, "Super Workstation"}
{0x0040ad, "SMA Regelsysteme Gmbh"}
{0x0040ae, "Delta Controls"}
{0x0040af, "Digital Products"}
{0x0040b0, "Bytex, Engineering"}
{0x0040b1, "Codonics"}
{0x0040b2, "Systemforschung"}
{0x0040b3, "ParTech"}
{0x0040b4, "Nextcom K.K."}
{0x0040b5, "Video Technology Computers"}
{0x0040b6, "Computerm "}
{0x0040b7, "Stealth Computer Systems"}
{0x0040b8, "Idea Associates"}
{0x0040b9, "Macq Electronique SA"}
{0x0040ba, "Alliant Computer Systems"}
{0x0040bb, "Goldstar Cable CO."}
{0x0040bc, "Algorithmics"}
{0x0040bd, "Starlight Networks"}
{0x0040be, "Boeing Defense & Space"}
{0x0040bf, "Channel Systems Intern'l"}
{0x0040c0, "Vista Controls"}
{0x0040c1, "Bizerba-werke Wilheim Kraut"}
{0x0040c2, "Applied Computing Devices"}
{0x0040c3, "Fischer AND Porter CO."}
{0x0040c4, "Kinkei System"}
{0x0040c5, "Micom Communications"}
{0x0040c6, "Fibernet Research"}
{0x0040c7, "Ruby Tech"}
{0x0040c8, "Milan Technology"}
{0x0040c9, "Ncube"}
{0x0040ca, "First Internat'l Computer"}
{0x0040cb, "Lanwan Technologies"}
{0x0040cc, "Silcom Manuf'g Technology"}
{0x0040cd, "Tera Microsystems"}
{0x0040ce, "Net-source"}
{0x0040cf, "Strawberry TREE"}
{0x0040d0, "Mitac International"}
{0x0040d1, "Fukuda Denshi CO."}
{0x0040d2, "Pagine"}
{0x0040d3, "Kimpsion International"}
{0x0040d4, "Gage Talker"}
{0x0040d5, "Sartorius Mechatronics T&H GmbH "}
{0x0040d6, "Locamation B.V."}
{0x0040d7, "Studio GEN"}
{0x0040d8, "Ocean Office Automation"}
{0x0040d9, "American Megatrends"}
{0x0040da, "Telspec"}
{0x0040db, "Advanced Technical Solutions"}
{0x0040dc, "Tritec Electronic Gmbh"}
{0x0040dd, "Hong Technologies"}
{0x0040de, "Elsag Datamat spa"}
{0x0040df, "Digalog Systems"}
{0x0040e0, "Atomwide"}
{0x0040e1, "Marner International"}
{0x0040e2, "Mesa Ridge Technologies"}
{0x0040e3, "Quin Systems"}
{0x0040e4, "E-M Technology"}
{0x0040e5, "Sybus"}
{0x0040e6, "C.a.e.n."}
{0x0040e7, "Arnos Instruments & Computer"}
{0x0040e8, "Charles River Data Systems"}
{0x0040e9, "Accord Systems"}
{0x0040ea, "Plain Tree Systems"}
{0x0040eb, "Martin Marietta"}
{0x0040ec, "Mikasa System Engineering"}
{0x0040ed, "Network Controls Int'natl"}
{0x0040ee, "Optimem"}
{0x0040ef, "Hypercom"}
{0x0040f0, "MicroBrain"}
{0x0040f1, "Chuo Electronics CO."}
{0x0040f2, "Janich & Klass Computertechnik"}
{0x0040f3, "Netcor"}
{0x0040f4, "Cameo Communications"}
{0x0040f5, "OEM Engines"}
{0x0040f6, "Katron Computers"}
{0x0040f7, "Polaroid"}
{0x0040f8, "Systemhaus Discom"}
{0x0040f9, "Combinet"}
{0x0040fa, "Microboards"}
{0x0040fb, "Cascade Communications"}
{0x0040fc, "IBR Computer Technik Gmbh"}
{0x0040fd, "LXE"}
{0x0040fe, "Symplex Communications"}
{0x0040ff, "Telebit"}
{0x0041b4, "Wuxi Zhongxing Optoelectronics Technology Co."}
{0x004252, "RLX Technologies"}
{0x0043ff, "Ketron S.r.l."}
{0x004501, "Versus Technology"}
{0x00464b, "Huawei Technologies Co."}
{0x005000, "Nexo Communications"}
{0x005001, "Yamashita Systems"}
{0x005002, "Omnisec AG"}
{0x005003, "Xrite"}
{0x005004, "3com"}
{0x005006, "TAC AB"}
{0x005007, "Siemens Telecommunication Systems Limited"}
{0x005008, "Tiva Microcomputer (tmc)"}
{0x005009, "Philips Broadband Networks"}
{0x00500a, "Iris Technologies"}
{0x00500b, "Cisco Systems"}
{0x00500c, "e-Tek Labs"}
{0x00500d, "Satori Electoric CO."}
{0x00500e, "Chromatis Networks"}
{0x00500f, "Cisco Systems"}
{0x005010, "NovaNET Learning"}
{0x005012, "CBL - Gmbh"}
{0x005013, "Chaparral Network Storage"}
{0x005014, "Cisco Systems"}
{0x005015, "Bright Star Engineering"}
{0x005016, "Sst/woodhead Industries"}
{0x005017, "RSR S.r.l."}
{0x005018, "AMIT"}
{0x005019, "Spring Tide Networks"}
{0x00501a, "IQinVision"}
{0x00501b, "ABL Canada"}
{0x00501c, "Jatom Systems"}
{0x00501e, "Miranda Technologies"}
{0x00501f, "MRG Systems"}
{0x005020, "Mediastar CO."}
{0x005021, "EIS International"}
{0x005022, "Zonet Technology"}
{0x005023, "PG Design Electronics"}
{0x005024, "Navic Systems"}
{0x005026, "Cosystems"}
{0x005027, "Genicom"}
{0x005028, "Aval Communications"}
{0x005029, "1394 Printer Working Group"}
{0x00502a, "Cisco Systems"}
{0x00502b, "Genrad"}
{0x00502c, "Soyo Computer"}
{0x00502d, "Accel"}
{0x00502e, "Cambex"}
{0x00502f, "TollBridge Technologies"}
{0x005030, "Future Plus Systems"}
{0x005031, "Aeroflex Laboratories"}
{0x005032, "Picazo Communications"}
{0x005033, "Mayan Networks"}
{0x005036, "Netcam"}
{0x005037, "Koga Electronics CO."}
{0x005038, "Dain Telecom CO."}
{0x005039, "Mariner Networks"}
{0x00503a, "Datong Electronics"}
{0x00503b, "Mediafire"}
{0x00503c, "Tsinghua Novel Electronics"}
{0x00503e, "Cisco Systems"}
{0x00503f, "Anchor Games"}
{0x005040, "Panasonic Electric Works Co."}
{0x005041, "Coretronic"}
{0x005042, "SCI Manufacturing Singapore PTE"}
{0x005043, "Marvell Semiconductor"}
{0x005044, "Asaca"}
{0x005045, "Rioworks Solutions"}
{0x005046, "Menicx International CO."}
{0x005047, "Private"}
{0x005048, "Infolibria"}
{0x005049, "Arbor Networks"}
{0x00504a, "Elteco A.S."}
{0x00504b, "Barconet N.V."}
{0x00504c, "Galil Motion Control"}
{0x00504d, "Tokyo Electron Device Limited"}
{0x00504e, "Sierra Monitor"}
{0x00504f, "Olencom Electronics"}
{0x005050, "Cisco Systems"}
{0x005051, "Iwatsu Electric CO."}
{0x005052, "Tiara Networks"}
{0x005053, "Cisco Systems"}
{0x005054, "Cisco Systems"}
{0x005055, "Doms A/S"}
{0x005056, "VMware"}
{0x005057, "Broadband Access Systems"}
{0x005058, "VegaStream Group Limted"}
{0x005059, "iBAHN"}
{0x00505a, "Network Alchemy"}
{0x00505b, "Kawasaki LSI U.s.a."}
{0x00505c, "Tundo"}
{0x00505e, "Digitek Micrologic S.A."}
{0x00505f, "Brand Innovators"}
{0x005060, "Tandberg Telecom AS"}
{0x005062, "Kouwell Electronics  **"}
{0x005063, "OY Comsel System AB"}
{0x005064, "CAE Electronics"}
{0x005065, "TDK-Lambda"}
{0x005066, "AtecoM GmbH advanced telecomunication modules"}
{0x005067, "Aerocomm"}
{0x005068, "Electronic Industries Association"}
{0x005069, "PixStream Incorporated"}
{0x00506a, "Edeva"}
{0x00506b, "Spx-ateg"}
{0x00506c, "Beijer Electronics Products AB"}
{0x00506d, "Videojet Systems"}
{0x00506e, "Corder Engineering"}
{0x00506f, "G-connect"}
{0x005070, "Chaintech Computer CO."}
{0x005071, "Aiwa CO."}
{0x005072, "Corvis"}
{0x005073, "Cisco Systems"}
{0x005074, "Advanced Hi-tech"}
{0x005075, "Kestrel Solutions"}
{0x005076, "IBM"}
{0x005077, "Prolific Technology"}
{0x005078, "Megaton House"}
{0x005079, "Private"}
{0x00507a, "Xpeed"}
{0x00507b, "Merlot Communications"}
{0x00507c, "Videocon AG"}
{0x00507d, "IFP"}
{0x00507e, "Newer Technology"}
{0x00507f, "DrayTek"}
{0x005080, "Cisco Systems"}
{0x005081, "Murata Machinery"}
{0x005082, "Foresson"}
{0x005083, "Gilbarco"}
{0x005084, "ATL Products"}
{0x005086, "Telkom SA"}
{0x005087, "Terasaki Electric CO."}
{0x005088, "Amano"}
{0x005089, "Safety Management Systems"}
{0x00508b, "Hewlett-Packard Company"}
{0x00508c, "RSI Systems"}
{0x00508d, "Abit Computer"}
{0x00508e, "Optimation"}
{0x00508f, "Asita Technologies Int'l"}
{0x005090, "Dctri"}
{0x005091, "Netaccess"}
{0x005092, "Rigaku Industrial"}
{0x005093, "Boeing"}
{0x005094, "Pace plc"}
{0x005095, "Peracom Networks"}
{0x005096, "Salix Technologies"}
{0x005097, "Mmc-embedded Computertechnik Gmbh"}
{0x005098, "Globaloop"}
{0x005099, "3com Europe"}
{0x00509a, "TAG Electronic Systems"}
{0x00509b, "Switchcore AB"}
{0x00509c, "Beta Research"}
{0x00509d, "THE Industree B.V."}
{0x00509e, "Les Technologies SoftAcoustik"}
{0x00509f, "Horizon Computer"}
{0x0050a0, "Delta Computer Systems"}
{0x0050a1, "Carlo Gavazzi"}
{0x0050a2, "Cisco Systems"}
{0x0050a3, "TransMedia Communications"}
{0x0050a4, "IO TECH"}
{0x0050a5, "Capitol Business Systems"}
{0x0050a6, "Optronics"}
{0x0050a7, "Cisco Systems"}
{0x0050a8, "OpenCon Systems"}
{0x0050a9, "Moldat Wireless Technolgies"}
{0x0050aa, "Konica Minolta Holdings"}
{0x0050ab, "Naltec"}
{0x0050ac, "Maple Computer"}
{0x0050ad, "CommUnique Wireless"}
{0x0050ae, "Iwaki Electronics CO."}
{0x0050af, "Intergon"}
{0x0050b0, "Technology Atlanta"}
{0x0050b1, "Giddings & Lewis"}
{0x0050b2, "Brodel Automation"}
{0x0050b3, "Voiceboard"}
{0x0050b4, "Satchwell Control Systems"}
{0x0050b5, "Fichet-bauche"}
{0x0050b6, "Good WAY IND. CO."}
{0x0050b7, "Boser Technology CO."}
{0x0050b8, "Inova Computers Gmbh & CO. KG"}
{0x0050b9, "Xitron Technologies"}
{0x0050ba, "D-link"}
{0x0050bb, "CMS Technologies"}
{0x0050bc, "Hammer Storage Solutions"}
{0x0050bd, "Cisco Systems"}
{0x0050be, "Fast Multimedia AG"}
{0x0050bf, "Metalligence Technology"}
{0x0050c0, "Gatan"}
{0x0050c1, "Gemflex Networks"}
{0x0050c2, "Ieee Registration Authority"}
{0x0050c4, "IMD"}
{0x0050c5, "ADS Technologies"}
{0x0050c6, "Loop Telecommunication International"}
{0x0050c8, "Addonics Technologies"}
{0x0050c9, "Maspro Denkoh"}
{0x0050ca, "NET TO NET Technologies"}
{0x0050cb, "Jetter"}
{0x0050cc, "Xyratex"}
{0x0050cd, "Digianswer A/S"}
{0x0050ce, "LG International"}
{0x0050cf, "Vanlink Communication Technology Research Institute"}
{0x0050d0, "Minerva Systems"}
{0x0050d1, "Cisco Systems"}
{0x0050d2, "CMC Electronics"}
{0x0050d3, "Digital Audio Processing"}
{0x0050d4, "Joohong Information"}
{0x0050d5, "AD Systems"}
{0x0050d6, "Atlas Copco Tools AB"}
{0x0050d7, "Telstrat"}
{0x0050d8, "Unicorn Computer"}
{0x0050d9, "Engetron-engenharia Eletronica IND. e COM. Ltda"}
{0x0050da, "3com"}
{0x0050db, "Contemporary Control"}
{0x0050dc, "TAS Telefonbau A. Schwabe Gmbh & CO. KG"}
{0x0050dd, "Serra Soldadura"}
{0x0050de, "Signum Systems"}
{0x0050df, "AirFiber"}
{0x0050e1, "NS Tech Electronics SDN BHD"}
{0x0050e2, "Cisco Systems"}
{0x0050e3, "Motorola"}
{0x0050e4, "Apple Computer"}
{0x0050e6, "Hakusan"}
{0x0050e7, "Paradise Innovations (asia)"}
{0x0050e8, "Nomadix"}
{0x0050ea, "XEL Communications"}
{0x0050eb, "Alpha-top"}
{0x0050ec, "Olicom A/S"}
{0x0050ed, "Anda Networks"}
{0x0050ee, "TEK Digitel"}
{0x0050ef, "SPE Systemhaus GmbH"}
{0x0050f0, "Cisco Systems"}
{0x0050f1, "Intel"}
{0x0050f2, "Microsoft"}
{0x0050f3, "Global NET Information CO."}
{0x0050f4, "Sigmatek Gmbh & CO. KG"}
{0x0050f6, "Pan-international Industrial"}
{0x0050f7, "Venture Manufacturing (singapore)"}
{0x0050f8, "Entrega Technologies"}
{0x0050f9, "Sensormatic ACD"}
{0x0050fa, "Oxtel"}
{0x0050fb, "VSK Electronics"}
{0x0050fc, "Edimax Technology CO."}
{0x0050fd, "Visioncomm CO."}
{0x0050fe, "Pctvnet ASA"}
{0x0050ff, "Hakko Electronics CO."}
{0x005218, "Wuxi Keboda ElectronLtd"}
{0x0054af, "Continental Automotive Systems"}
{0x005cb1, "Gospell Digital Technology CO."}
{0x006000, "Xycom"}
{0x006001, "InnoSys"}
{0x006002, "Screen Subtitling Systems"}
{0x006003, "Teraoka Weigh System PTE"}
{0x006004, "Computadores Modulares SA"}
{0x006005, "Feedback Data"}
{0x006006, "Sotec CO."}
{0x006007, "Acres Gaming"}
{0x006008, "3com"}
{0x006009, "Cisco Systems"}
{0x00600a, "Sord Computer"}
{0x00600b, "Logware Gmbh"}
{0x00600c, "Eurotech"}
{0x00600d, "Digital Logic GmbH"}
{0x00600e, "Wavenet International"}
{0x00600f, "Westell"}
{0x006010, "Network Machines"}
{0x006011, "Crystal Semiconductor"}
{0x006012, "Power Computing"}
{0x006013, "Netstal Maschinen AG"}
{0x006014, "Edec CO."}
{0x006015, "Net2net"}
{0x006016, "Clariion"}
{0x006017, "Tokimec"}
{0x006018, "Stellar ONE"}
{0x006019, "Roche Diagnostics"}
{0x00601a, "Keithley Instruments"}
{0x00601b, "Mesa Electronics"}
{0x00601c, "Telxon"}
{0x00601d, "Lucent Technologies"}
{0x00601e, "Softlab"}
{0x00601f, "Stallion Technologies"}
{0x006020, "Pivotal Networking"}
{0x006021, "DSC"}
{0x006022, "Vicom Systems"}
{0x006023, "Pericom Semiconductor"}
{0x006024, "Gradient Technologies"}
{0x006025, "Active Imaging PLC"}
{0x006026, "Viking Modular Solutions"}
{0x006027, "Superior Modular Products"}
{0x006028, "Macrovision"}
{0x006029, "Cary Peripherals"}
{0x00602a, "Symicron Computer Communications"}
{0x00602b, "Peak Audio"}
{0x00602c, "Linx Data Terminals"}
{0x00602d, "Alerton Technologies"}
{0x00602e, "Cyclades"}
{0x00602f, "Cisco Systems"}
{0x006030, "Village Tronic Entwicklung"}
{0x006031, "HRK Systems"}
{0x006032, "I-cube"}
{0x006033, "Acuity Imaging"}
{0x006034, "Robert Bosch Gmbh"}
{0x006035, "Dallas Semiconductor"}
{0x006036, "AIT Austrian Institute of Technology GmbH"}
{0x006037, "NXP Semiconductors"}
{0x006038, "Nortel Networks"}
{0x006039, "SanCom Technology"}
{0x00603a, "Quick Controls"}
{0x00603b, "Amtec spa"}
{0x00603c, "Hagiwara Sys-com CO."}
{0x00603d, "3CX"}
{0x00603e, "Cisco Systems"}
{0x00603f, "Patapsco Designs"}
{0x006040, "Netro"}
{0x006041, "Yokogawa Electric"}
{0x006042, "TKS (usa)"}
{0x006043, "iDirect"}
{0x006044, "Litton/poly-scientific"}
{0x006045, "Pathlight Technologies"}
{0x006046, "Vmetro"}
{0x006047, "Cisco Systems"}
{0x006048, "EMC"}
{0x006049, "Vina Technologies"}
{0x00604a, "Saic Ideas Group"}
{0x00604b, "Safe-com GmbH & Co. KG"}
{0x00604c, "Sagem Communication"}
{0x00604d, "MMC Networks"}
{0x00604e, "Cycle Computer"}
{0x00604f, "Suzuki MFG. CO."}
{0x006050, "Internix"}
{0x006051, "Quality Semiconductor"}
{0x006052, "Peripherals Enterprise CO."}
{0x006053, "Toyoda Machine Works"}
{0x006054, "Controlware Gmbh"}
{0x006055, "Cornell University"}
{0x006056, "Network Tools"}
{0x006057, "Murata Manufacturing CO."}
{0x006058, "Copper Mountain Communications"}
{0x006059, "Technical Communications"}
{0x00605a, "Celcore"}
{0x00605b, "IntraServer Technology"}
{0x00605c, "Cisco Systems"}
{0x00605d, "Scanivalve"}
{0x00605e, "Liberty Technology Networking"}
{0x00605f, "Nippon Unisoft"}
{0x006060, "Dawning Technologies"}
{0x006061, "Whistle Communications"}
{0x006062, "Telesync"}
{0x006063, "Psion Dacom PLC."}
{0x006064, "Netcomm Limited"}
{0x006065, "Bernecker & Rainer Industrie-elektronic Gmbh"}
{0x006066, "Lacroix Trafic"}
{0x006067, "Acer Netxus"}
{0x006068, "Dialogic"}
{0x006069, "Brocade Communications Systems"}
{0x00606a, "Mitsubishi Wireless Communications."}
{0x00606b, "Synclayer"}
{0x00606c, "Arescom"}
{0x00606d, "Digital Equipment"}
{0x00606e, "Davicom Semiconductor"}
{0x00606f, "Clarion OF America"}
{0x006070, "Cisco Systems"}
{0x006071, "Midas LAB"}
{0x006072, "VXL Instruments, Limited"}
{0x006073, "Redcreek Communications"}
{0x006074, "QSC Audio Products"}
{0x006075, "Pentek"}
{0x006076, "Schlumberger Technologies Retail Petroleum Systems"}
{0x006077, "Prisa Networks"}
{0x006078, "Power Measurement"}
{0x006079, "Mainstream Data"}
{0x00607a, "DVS GmbH"}
{0x00607b, "Fore Systems"}
{0x00607c, "WaveAccess"}
{0x00607d, "Sentient Networks"}
{0x00607e, "Gigalabs"}
{0x00607f, "Aurora Technologies"}
{0x006080, "Microtronix Datacom"}
{0x006081, "Tv/com International"}
{0x006082, "Novalink Technologies"}
{0x006083, "Cisco Systems"}
{0x006084, "Digital Video"}
{0x006085, "Storage Concepts"}
{0x006086, "Logic Replacement TECH."}
{0x006087, "Kansai Electric CO."}
{0x006088, "White Mountain DSP"}
{0x006089, "Xata"}
{0x00608a, "Citadel Computer"}
{0x00608b, "ConferTech International"}
{0x00608c, "3com"}
{0x00608d, "Unipulse"}
{0x00608e, "HE Electronics, Technologie & Systemtechnik Gmbh"}
{0x00608f, "Tekram Technology CO."}
{0x006090, "Artiza Networks"}
{0x006091, "First Pacific Networks"}
{0x006092, "Micro/sys"}
{0x006093, "Varian"}
{0x006094, "IBM"}
{0x006095, "Accu-time Systems"}
{0x006096, "T.S. Microtech"}
{0x006097, "3com"}
{0x006098, "HT Communications"}
{0x006099, "SBE"}
{0x00609a, "NJK Techno CO."}
{0x00609b, "Astro-med"}
{0x00609c, "Perkin-Elmer Incorporated"}
{0x00609d, "PMI Food Equipment Group"}
{0x00609e, "ASC X3 - Information Technology Standards Secretariats"}
{0x00609f, "Phast"}
{0x0060a0, "Switched Network Technologies"}
{0x0060a1, "VPNet"}
{0x0060a2, "Nihon Unisys Limited CO."}
{0x0060a3, "Continuum Technology"}
{0x0060a4, "Grinaker System Technologies"}
{0x0060a5, "Performance Telecom"}
{0x0060a6, "Particle Measuring Systems"}
{0x0060a7, "Microsens Gmbh & CO. KG"}
{0x0060a8, "Tidomat AB"}
{0x0060a9, "Gesytec MbH"}
{0x0060aa, "Intelligent Devices (idi)"}
{0x0060ab, "Larscom Incorporated"}
{0x0060ac, "Resilience"}
{0x0060ad, "MegaChips"}
{0x0060ae, "Trio Information Systems AB"}
{0x0060af, "Pacific Micro DATA"}
{0x0060b0, "Hewlett-packard CO."}
{0x0060b1, "Input/output"}
{0x0060b2, "Process Control"}
{0x0060b3, "Z-com"}
{0x0060b4, "Glenayre R&D"}
{0x0060b5, "Keba Gmbh"}
{0x0060b6, "Land Computer CO."}
{0x0060b7, "Channelmatic"}
{0x0060b8, "Corelis"}
{0x0060b9, "NEC Infrontia"}
{0x0060ba, "Sahara Networks"}
{0x0060bb, "Cabletron - Netlink"}
{0x0060bc, "KeunYoung Electronics & Communication Co."}
{0x0060bd, "Hubbell-pulsecom"}
{0x0060be, "Webtronics"}
{0x0060bf, "Macraigor Systems"}
{0x0060c0, "Nera Networks AS"}
{0x0060c1, "WaveSpan"}
{0x0060c2, "MPL AG"}
{0x0060c3, "Netvision"}
{0x0060c4, "Soliton Systems K.K."}
{0x0060c5, "Ancot"}
{0x0060c6, "DCS AG"}
{0x0060c7, "Amati Communications"}
{0x0060c8, "Kuka Welding Systems & Robots"}
{0x0060c9, "ControlNet"}
{0x0060ca, "Harmonic Systems Incorporated"}
{0x0060cb, "Hitachi Zosen"}
{0x0060cc, "Emtrak, Incorporated"}
{0x0060cd, "VideoServer"}
{0x0060ce, "Acclaim Communications"}
{0x0060cf, "Alteon Networks"}
{0x0060d0, "Snmp Research Incorporated"}
{0x0060d1, "Cascade Communications"}
{0x0060d2, "Lucent Technologies Taiwan Telecommunications CO."}
{0x0060d3, "At&t"}
{0x0060d4, "Eldat Communication"}
{0x0060d5, "Miyachi Technos"}
{0x0060d6, "NovAtel Wireless Technologies"}
{0x0060d7, "Ecole Polytechnique Federale DE Lausanne (epfl)"}
{0x0060d8, "Elmic Systems"}
{0x0060d9, "Transys Networks"}
{0x0060da, "JBM Electronics CO."}
{0x0060db, "NTP Elektronik A/S"}
{0x0060dc, "Toyo Network Systems  & System Integration Co."}
{0x0060dd, "Myricom"}
{0x0060de, "Kayser-Threde GmbH"}
{0x0060df, "Brocade Communications Systems"}
{0x0060e0, "Axiom Technology CO."}
{0x0060e1, "Orckit Communications"}
{0x0060e2, "Quest Engineering & Development"}
{0x0060e3, "Arbin Instruments"}
{0x0060e4, "Compuserve"}
{0x0060e5, "Fuji Automation CO."}
{0x0060e6, "Shomiti Systems Incorporated"}
{0x0060e7, "Randata"}
{0x0060e8, "Hitachi Computer Products (america)"}
{0x0060e9, "Atop Technologies"}
{0x0060ea, "StreamLogic"}
{0x0060eb, "Fourthtrack Systems"}
{0x0060ec, "Hermary Opto Electronics"}
{0x0060ed, "Ricardo Test Automation"}
{0x0060ee, "Apollo"}
{0x0060ef, "Flytech Technology CO."}
{0x0060f0, "Johnson & Johnson Medical"}
{0x0060f1, "EXP Computer"}
{0x0060f2, "Lasergraphics"}
{0x0060f3, "Performance Analysis Broadband, Spirent plc"}
{0x0060f4, "Advanced Computer Solutions"}
{0x0060f5, "Icon WEST"}
{0x0060f6, "Nextest Communications Products"}
{0x0060f7, "Datafusion Systems"}
{0x0060f8, "Loran International Technologies"}
{0x0060f9, "Diamond Lane Communications"}
{0x0060fa, "Educational Technology Resources"}
{0x0060fb, "Packeteer"}
{0x0060fc, "Conservation Through Innovation"}
{0x0060fd, "NetICs"}
{0x0060fe, "Lynx System Developers"}
{0x0060ff, "QuVis"}
{0x006440, "Cisco Systems"}
{0x0064a6, "Maquet CardioVascular"}
{0x006b9e, "Vizio"}
{0x006ba0, "Shenzhen Universal Intellisys PTE"}
{0x006dfb, "Vutrix (UK)"}
{0x0070b0, "M/a-com Companies"}
{0x0070b3, "Data Recall"}
{0x00789e, "Sagemcom"}
{0x007f28, "Actiontec Electronics"}
{0x008000, "Multitech Systems"}
{0x008001, "Periphonics"}
{0x008002, "Satelcom (uk)"}
{0x008003, "Hytec Electronics"}
{0x008004, "Antlow Communications"}
{0x008005, "Cactus Computer"}
{0x008006, "Compuadd"}
{0x008007, "Dlog Nc-systeme"}
{0x008008, "Dynatech Computer Systems"}
{0x008009, "Jupiter Systems"}
{0x00800a, "Japan Computer"}
{0x00800b, "CSK"}
{0x00800c, "Videcom Limited"}
{0x00800d, "Vosswinkel F.U."}
{0x00800e, "Atlantix"}
{0x00800f, "Standard Microsystems"}
{0x008010, "Commodore International"}
{0x008011, "Digital Systems Int'l."}
{0x008012, "Integrated Measurement Systems"}
{0x008013, "Thomas-conrad"}
{0x008014, "Esprit Systems"}
{0x008015, "Seiko Systems"}
{0x008016, "Wandel AND Goltermann"}
{0x008017, "PFU Limited"}
{0x008018, "Kobe Steel"}
{0x008019, "Dayna Communications"}
{0x00801a, "Bell Atlantic"}
{0x00801b, "Kodiak Technology"}
{0x00801c, "Newport Systems Solutions"}
{0x00801d, "Integrated Inference Machines"}
{0x00801e, "Xinetron"}
{0x00801f, "Krupp Atlas Electronik Gmbh"}
{0x008020, "Network Products"}
{0x008021, "Alcatel Canada"}
{0x008022, "Scan-optics"}
{0x008023, "Integrated Business Networks"}
{0x008024, "Kalpana"}
{0x008025, "Stollmann Gmbh"}
{0x008026, "Network Products"}
{0x008027, "Adaptive Systems"}
{0x008028, "Tradpost (hk)"}
{0x008029, "Eagle Technology"}
{0x00802a, "Test Systems & Simulations"}
{0x00802b, "Integrated Marketing CO"}
{0x00802c, "THE Sage Group PLC"}
{0x00802d, "Xylogics"}
{0x00802e, "Castle Rock Computing"}
{0x00802f, "National Instruments"}
{0x008030, "Nexus Electronics"}
{0x008031, "Basys"}
{0x008032, "Access CO."}
{0x008033, "EMS Aviation"}
{0x008034, "SMT Goupil"}
{0x008035, "Technology Works"}
{0x008036, "Reflex Manufacturing Systems"}
{0x008037, "Ericsson Group"}
{0x008038, "Data Research & Applications"}
{0x008039, "Alcatel STC Australia"}
{0x00803a, "Varityper"}
{0x00803b, "APT Communications"}
{0x00803c, "TVS Electronics"}
{0x00803d, "Surigiken CO."}
{0x00803e, "Synernetics"}
{0x00803f, "Tatung Company"}
{0x008040, "John Fluke Manufacturing CO."}
{0x008041, "VEB Kombinat Robotron"}
{0x008042, "Emerson Network Power"}
{0x008043, "Networld"}
{0x008044, "Systech Computer"}
{0x008045, "Matsushita Electric IND. CO"}
{0x008046, "University OF Toronto"}
{0x008047, "In-net"}
{0x008048, "Compex Incorporated"}
{0x008049, "Nissin Electric CO."}
{0x00804a, "Pro-log"}
{0x00804b, "Eagle Technologiesltd."}
{0x00804c, "Contec CO."}
{0x00804d, "Cyclone Microsystems"}
{0x00804e, "Apex Computer Company"}
{0x00804f, "Daikin Industries"}
{0x008050, "Ziatech"}
{0x008051, "Fibermux"}
{0x008052, "Technically Elite Concepts"}
{0x008053, "Intellicom"}
{0x008054, "Frontier Technologies"}
{0x008055, "Fermilab"}
{0x008056, "Sphinx Elektronik Gmbh"}
{0x008057, "Adsoft"}
{0x008058, "Printer Systems"}
{0x008059, "Stanley Electric CO."}
{0x00805a, "Tulip Computers Internat'l B.V"}
{0x00805b, "Condor Systems"}
{0x00805c, "Agilis"}
{0x00805d, "Canstar"}
{0x00805e, "LSI Logic"}
{0x00805f, "Hewlett-Packard Company"}
{0x008060, "Network Interface"}
{0x008061, "Litton Systems"}
{0x008062, "Interface  CO."}
{0x008063, "Hirschmann Automation and Control GmbH"}
{0x008064, "Wyse Technology"}
{0x008065, "Cybergraphic Systems"}
{0x008066, "Arcom Control Systems"}
{0x008067, "Square D Company"}
{0x008068, "Yamatech Scientific"}
{0x008069, "Computone Systems"}
{0x00806a, "ERI (empac Research)"}
{0x00806b, "Schmid Telecommunication"}
{0x00806c, "Cegelec Projects"}
{0x00806d, "Century Systems"}
{0x00806e, "Nippon Steel"}
{0x00806f, "Onelan"}
{0x008070, "Computadoras Micron"}
{0x008071, "SAI Technology"}
{0x008072, "Microplex Systems"}
{0x008073, "DWB Associates"}
{0x008074, "Fisher Controls"}
{0x008075, "Parsytec Gmbh"}
{0x008076, "Mcnc"}
{0x008077, "Brother Industries"}
{0x008078, "Practical Peripherals"}
{0x008079, "Microbus Designs"}
{0x00807a, "Aitech Systems"}
{0x00807b, "Artel Communications"}
{0x00807c, "Fibercom"}
{0x00807d, "Equinox Systems"}
{0x00807e, "Southern Pacific"}
{0x00807f, "Dy-4 Incorporated"}
{0x008080, "Datamedia"}
{0x008081, "Kendall Square Research"}
{0x008082, "PEP Modular Computers Gmbh"}
{0x008083, "Amdahl"}
{0x008084, "THE Cloud"}
{0x008085, "H-three Systems"}
{0x008086, "Computer Generation"}
{0x008087, "OKI Electric Industry CO."}
{0x008088, "Victor Company OF Japan"}
{0x008089, "Tecnetics (pty)"}
{0x00808a, "Summit Microsystems"}
{0x00808b, "Dacoll Limited"}
{0x00808c, "NetScout Systems"}
{0x00808d, "Westcoast Technology B.V."}
{0x00808e, "Radstone Technology"}
{0x00808f, "C. Itoh Electronics"}
{0x008090, "Microtek International"}
{0x008091, "Tokyo Electric Co."}
{0x008092, "Silex Technology"}
{0x008093, "Xyron"}
{0x008094, "Alfa Laval Automation AB"}
{0x008095, "Basic Merton Handelsges.m.b.h."}
{0x008096, "Human Designed Systems"}
{0x008097, "Centralp Automatismes"}
{0x008098, "TDK"}
{0x008099, "Klockner Moeller IPC"}
{0x00809a, "Novus Networks"}
{0x00809b, "Justsystem"}
{0x00809c, "Luxcom"}
{0x00809d, "Commscraft"}
{0x00809e, "Datus Gmbh"}
{0x00809f, "Alcatel Business Systems"}
{0x0080a0, "Edisa Hewlett Packard S/A"}
{0x0080a1, "Microtest"}
{0x0080a2, "Creative Electronic Systems"}
{0x0080a3, "Lantronix"}
{0x0080a4, "Liberty Electronics"}
{0x0080a5, "Speed International"}
{0x0080a6, "Republic Technology"}
{0x0080a7, "Honeywell International"}
{0x0080a8, "Vitacom"}
{0x0080a9, "Clearpoint Research"}
{0x0080aa, "Maxpeed"}
{0x0080ab, "Dukane Network Integration"}
{0x0080ac, "Imlogix, Division OF Genesys"}
{0x0080ad, "Cnet Technology"}
{0x0080ae, "Hughes Network Systems"}
{0x0080af, "Allumer CO."}
{0x0080b0, "Advanced Information"}
{0x0080b1, "Softcom A/S"}
{0x0080b2, "Network Equipment Technologies"}
{0x0080b3, "Aval Data"}
{0x0080b4, "Sophia Systems"}
{0x0080b5, "United Networks"}
{0x0080b6, "Themis Computer"}
{0x0080b7, "Stellar Computer"}
{0x0080b8, "BUG, Incorporated"}
{0x0080b9, "Arche Technoligies"}
{0x0080ba, "Specialix (asia) PTE"}
{0x0080bb, "Hughes LAN Systems"}
{0x0080bc, "Hitachi Engineering CO."}
{0x0080bd, "THE Furukawa Electric CO."}
{0x0080be, "Aries Research"}
{0x0080bf, "Takaoka Electric MFG. CO."}
{0x0080c0, "Penril Datacomm"}
{0x0080c1, "Lanex"}
{0x0080c2, "Ieee 802.1 Committee"}
{0x0080c3, "Bicc Information Systems & SVC"}
{0x0080c4, "Document Technologies"}
{0x0080c5, "Novellco DE Mexico"}
{0x0080c6, "National Datacomm"}
{0x0080c7, "Xircom"}
{0x0080c8, "D-link Systems"}
{0x0080c9, "Alberta Microelectronic Centre"}
{0x0080ca, "Netcom Research Incorporated"}
{0x0080cb, "Falco Data Products"}
{0x0080cc, "Microwave Bypass Systems"}
{0x0080cd, "Micronics Computer"}
{0x0080ce, "Broadcast Television Systems"}
{0x0080cf, "Embedded Performance"}
{0x0080d0, "Computer Peripherals"}
{0x0080d1, "Kimtron"}
{0x0080d2, "Shinnihondenko CO."}
{0x0080d3, "Shiva"}
{0x0080d4, "Chase Research"}
{0x0080d5, "Cadre Technologies"}
{0x0080d6, "Nuvotech"}
{0x0080d7, "Fantum Engineering"}
{0x0080d8, "Network Peripherals"}
{0x0080d9, "EMK Elektronik GmbH & Co. KG"}
{0x0080da, "Bruel & Kjaer Sound & Vibration Measurement A/S"}
{0x0080db, "Graphon"}
{0x0080dc, "Picker International"}
{0x0080dd, "GMX/gimix"}
{0x0080de, "Gipsi S.A."}
{0x0080df, "ADC Codenoll Technology"}
{0x0080e0, "XTP Systems"}
{0x0080e1, "Stmicroelectronics"}
{0x0080e2, "T.d.i. CO."}
{0x0080e3, "Coral Network"}
{0x0080e4, "Northwest Digital Systems"}
{0x0080e5, "LSI Logic"}
{0x0080e6, "Peer Networks"}
{0x0080e7, "Lynwood Scientific DEV."}
{0x0080e8, "Cumulus Corporatiion"}
{0x0080e9, "Madge"}
{0x0080ea, "Adva Optical Networking"}
{0x0080eb, "Compcontrol B.V."}
{0x0080ec, "Supercomputing Solutions"}
{0x0080ed, "IQ Technologies"}
{0x0080ee, "Thomson CSF"}
{0x0080ef, "Rational"}
{0x0080f0, "Panasonic Communications Co."}
{0x0080f1, "Opus Systems"}
{0x0080f2, "Raycom Systems"}
{0x0080f3, "SUN Electronics"}
{0x0080f4, "Telemecanique Electrique"}
{0x0080f5, "Quantel"}
{0x0080f6, "Synergy Microsystems"}
{0x0080f7, "Zenith Electronics"}
{0x0080f8, "Mizar"}
{0x0080f9, "Heurikon"}
{0x0080fa, "RWT Gmbh"}
{0x0080fb, "BVM Limited"}
{0x0080fc, "Avatar"}
{0x0080fd, "Exsceed Corpration"}
{0x0080fe, "Azure Technologies"}
{0x0080ff, "SOC. DE Teleinformatique RTC"}
{0x008c10, "Black Box"}
{0x008cfa, "Inventec"}
{0x008d4e, "Cjsc NII STT"}
{0x008dda, "Link One Co."}
{0x009000, "Diamond Multimedia"}
{0x009001, "Nishimu Electronics Industries CO."}
{0x009002, "Allgon AB"}
{0x009003, "Aplio"}
{0x009004, "3com Europe"}
{0x009005, "Protech Systems CO."}
{0x009006, "Hamamatsu Photonics K.K."}
{0x009007, "Domex Technology"}
{0x009008, "HanA Systems"}
{0x009009, "i Controls"}
{0x00900a, "Proton Electronic Industrial CO."}
{0x00900b, "Lanner Electronics"}
{0x00900c, "Cisco Systems"}
{0x00900d, "Overland Storage"}
{0x00900e, "Handlink Technologies"}
{0x00900f, "Kawasaki Heavy Industries"}
{0x009010, "Simulation Laboratories"}
{0x009011, "Wavtrace"}
{0x009012, "Globespan Semiconductor"}
{0x009013, "Samsan"}
{0x009014, "Rotork Instruments"}
{0x009015, "Centigram Communications"}
{0x009016, "ZAC"}
{0x009017, "Zypcom"}
{0x009018, "ITO Electric Industry CO"}
{0x009019, "Hermes Electronics CO."}
{0x00901a, "Unisphere Solutions"}
{0x00901b, "Digital Controls"}
{0x00901c, "mps Software Gmbh"}
{0x00901d, "PEC (nz)"}
{0x00901e, "Selesta Ingegneria S.p.A."}
{0x00901f, "Adtec Productions"}
{0x009020, "Philips Analytical X-ray B.V."}
{0x009021, "Cisco Systems"}
{0x009022, "Ivex"}
{0x009023, "Zilog"}
{0x009024, "Pipelinks"}
{0x009025, "BAE Systems Australia (Electronic Systems)"}
{0x009026, "Advanced Switching Communications"}
{0x009027, "Intel"}
{0x009028, "Nippon Signal CO."}
{0x009029, "Crypto AG"}
{0x00902a, "Communication Devices"}
{0x00902b, "Cisco Systems"}
{0x00902c, "Data & Control Equipment"}
{0x00902d, "Data Electronics (aust.)"}
{0x00902e, "Namco Limited"}
{0x00902f, "Netcore Systems"}
{0x009030, "Honeywell-dating"}
{0x009031, "Mysticom"}
{0x009032, "Pelcombe Group"}
{0x009033, "Innovaphone AG"}
{0x009034, "Imagic"}
{0x009035, "Alpha Telecom"}
{0x009036, "ens"}
{0x009037, "Acucomm"}
{0x009038, "Fountain Technologies"}
{0x009039, "Shasta Networks"}
{0x00903a, "Nihon Media Tool"}
{0x00903b, "TriEMS Research Lab"}
{0x00903c, "Atlantic Network Systems"}
{0x00903d, "Biopac Systems"}
{0x00903e, "N.V. Philips Industrial Activities"}
{0x00903f, "Aztec Radiomedia"}
{0x009040, "Siemens Network Convergence"}
{0x009041, "Applied Digital Access"}
{0x009042, "ECCS"}
{0x009043, "Nichibei Denshi CO."}
{0x009044, "Assured Digital"}
{0x009045, "Marconi Communications"}
{0x009046, "Dexdyne"}
{0x009047, "Giga Fast E."}
{0x009048, "Zeal"}
{0x009049, "Entridia"}
{0x00904a, "Concur System Technologies"}
{0x00904b, "GemTek Technology Co."}
{0x00904c, "Epigram"}
{0x00904d, "Spec S.A."}
{0x00904e, "Delem BV"}
{0x00904f, "ABB Power T&D Company"}
{0x009050, "Teleste OY"}
{0x009051, "Ultimate Technology"}
{0x009052, "Selcom Elettronica S.r.l."}
{0x009053, "Daewoo Electronics CO."}
{0x009054, "Innovative Semiconductors"}
{0x009055, "Parker Hannifin Compumotor Division"}
{0x009056, "Telestream"}
{0x009057, "AANetcom"}
{0x009058, "Ultra Electronics, Command and Control Systems"}
{0x009059, "Telecom Device K.K."}
{0x00905a, "Dearborn Group"}
{0x00905b, "Raymond AND LAE Engineering"}
{0x00905c, "Edmi"}
{0x00905d, "Netcom Sicherheitstechnik Gmbh"}
{0x00905e, "Rauland-borg"}
{0x00905f, "Cisco Systems"}
{0x009060, "System Create"}
{0x009061, "Pacific Research & Engineering"}
{0x009062, "ICP Vortex Computersysteme Gmbh"}
{0x009063, "Coherent Communications Systems"}
{0x009064, "Thomson"}
{0x009065, "Finisar"}
{0x009066, "Troika Networks"}
{0x009067, "WalkAbout Computers"}
{0x009068, "DVT"}
{0x009069, "Juniper Networks"}
{0x00906a, "Turnstone Systems"}
{0x00906b, "Applied Resources"}
{0x00906c, "Sartorius Hamburg GmbH"}
{0x00906d, "Cisco Systems"}
{0x00906e, "Praxon"}
{0x00906f, "Cisco Systems"}
{0x009070, "NEO Networks"}
{0x009071, "Applied Innovation"}
{0x009072, "Simrad AS"}
{0x009073, "Gaio Technology"}
{0x009074, "Argon Networks"}
{0x009075, "NEC DO Brasil S.A."}
{0x009076, "FMT Aircraft Gate Support Systems AB"}
{0x009077, "Advanced Fibre Communications"}
{0x009078, "MER Telemanagement Solutions"}
{0x009079, "ClearOne"}
{0x00907a, "Polycom"}
{0x00907b, "E-tech"}
{0x00907c, "Digitalcast"}
{0x00907d, "Lake Communications"}
{0x00907e, "Vetronix"}
{0x00907f, "WatchGuard Technologies"}
{0x009080, "NOT Limited"}
{0x009081, "Aloha Networks"}
{0x009082, "Force Institute"}
{0x009083, "Turbo Communication"}
{0x009084, "Atech System"}
{0x009085, "Golden Enterprises"}
{0x009086, "Cisco Systems"}
{0x009087, "Itis"}
{0x009088, "Baxall Security"}
{0x009089, "Softcom Microsystems"}
{0x00908a, "Bayly Communications"}
{0x00908b, "PFU Systems"}
{0x00908c, "Etrend Electronics"}
{0x00908d, "Vickers Electronics Systems"}
{0x00908e, "Nortel Networks Broadband Access"}
{0x00908f, "Audio Codes"}
{0x009090, "I-bus"}
{0x009091, "DigitalScape"}
{0x009092, "Cisco Systems"}
{0x009093, "Nanao"}
{0x009094, "Osprey Technologies"}
{0x009095, "Universal Avionics"}
{0x009096, "Askey Computer"}
{0x009097, "Sycamore Networks"}
{0x009098, "SBC Designs"}
{0x009099, "Allied Telesis"}
{0x00909a, "ONE World Systems"}
{0x00909b, "Imaje"}
{0x00909c, "Motorola"}
{0x00909d, "NovaTech Process Solutions"}
{0x00909e, "Critical IO"}
{0x00909f, "Digi-data"}
{0x0090a0, "8X8"}
{0x0090a1, "Flying Pig Systems/High End Systems"}
{0x0090a2, "Cybertan Technology"}
{0x0090a3, "Corecess"}
{0x0090a4, "Altiga Networks"}
{0x0090a5, "Spectra Logic"}
{0x0090a6, "Cisco Systems"}
{0x0090a7, "Clientec"}
{0x0090a8, "NineTiles Networks"}
{0x0090a9, "Western Digital"}
{0x0090aa, "Indigo Active Vision Systems Limited"}
{0x0090ab, "Cisco Systems"}
{0x0090ac, "Optivision"}
{0x0090ad, "Aspect Electronics"}
{0x0090ae, "Italtel S.p.a."}
{0x0090af, "J. Morita MFG."}
{0x0090b0, "Vadem"}
{0x0090b1, "Cisco Systems"}
{0x0090b2, "Avici Systems"}
{0x0090b3, "Agranat Systems"}
{0x0090b4, "Willowbrook Technologies"}
{0x0090b5, "Nikon"}
{0x0090b6, "Fibex Systems"}
{0x0090b7, "Digital Lightwave"}
{0x0090b8, "Rohde & Schwarz Gmbh & CO. KG"}
{0x0090b9, "Beran Instruments"}
{0x0090ba, "Valid Networks"}
{0x0090bb, "Tainet Communication System"}
{0x0090bc, "Telemann CO."}
{0x0090bd, "Omnia Communications"}
{0x0090be, "Ibc/integrated Business Computers"}
{0x0090bf, "Cisco Systems"}
{0x0090c0, "K.J. LAW Engineers"}
{0x0090c1, "Peco II"}
{0x0090c2, "JK microsystems"}
{0x0090c3, "Topic Semiconductor"}
{0x0090c4, "Javelin Systems"}
{0x0090c5, "Internet Magic"}
{0x0090c6, "Optim Systems"}
{0x0090c7, "Icom"}
{0x0090c8, "Waverider Communications (canada)"}
{0x0090c9, "Dpac Technologies"}
{0x0090ca, "Accord Video Telecommunications"}
{0x0090cb, "Wireless OnLine"}
{0x0090cc, "Planex Communications"}
{0x0090cd, "Ent-empresa Nacional DE Telecommunicacoes"}
{0x0090ce, "Tetra Gmbh"}
{0x0090cf, "Nortel"}
{0x0090d0, "Thomson Telecom Belgium"}
{0x0090d1, "Leichu Enterprise CO."}
{0x0090d2, "Artel Video Systems"}
{0x0090d3, "Giesecke & Devrient Gmbh"}
{0x0090d4, "BindView Development"}
{0x0090d5, "Euphonix"}
{0x0090d6, "Crystal Group"}
{0x0090d7, "NetBoost"}
{0x0090d8, "Whitecross Systems"}
{0x0090d9, "Cisco Systems"}
{0x0090da, "Dynarc"}
{0x0090db, "Next Level Communications"}
{0x0090dc, "Teco Information Systems"}
{0x0090dd, "THE Miharu Communications CO."}
{0x0090de, "Cardkey Systems"}
{0x0090df, "Mitsubishi Chemical America"}
{0x0090e0, "Systran"}
{0x0090e1, "Telena S.p.a."}
{0x0090e2, "Distributed Processing Technology"}
{0x0090e3, "Avex Electronics"}
{0x0090e4, "NEC America"}
{0x0090e5, "Teknema"}
{0x0090e6, "ALi"}
{0x0090e7, "Horsch Elektronik AG"}
{0x0090e8, "Moxa Technologies"}
{0x0090e9, "Janz Computer AG"}
{0x0090ea, "Alpha Technologies"}
{0x0090eb, "Sentry Telecom Systems"}
{0x0090ec, "Pyrescom"}
{0x0090ed, "Central System Research CO."}
{0x0090ee, "Personal Communications Technologies"}
{0x0090ef, "Integrix"}
{0x0090f0, "Harmonic Video Systems"}
{0x0090f1, "DOT Hill Systems"}
{0x0090f2, "Cisco Systems"}
{0x0090f3, "Aspect Communications"}
{0x0090f4, "Lightning Instrumentation"}
{0x0090f5, "Clevo CO."}
{0x0090f6, "Escalate Networks"}
{0x0090f7, "Nbase Communications"}
{0x0090f8, "Mediatrix Telecom"}
{0x0090f9, "Leitch"}
{0x0090fa, "Emulex"}
{0x0090fb, "Portwell"}
{0x0090fc, "Network Computing Devices"}
{0x0090fd, "CopperCom"}
{0x0090fe, "Elecom CO.,  (laneed DIV.)"}
{0x0090ff, "Tellus Technology"}
{0x0091d6, "Crystal Group"}
{0x0091fa, "Synapse Product Development"}
{0x009363, "Uni-Link Technology Co."}
{0x0097ff, "Heimann Sensor GmbH"}
{0x009c02, "Hewlett-Packard Company"}
{0x009d8e, "Cardiac Recorders"}
{0x00a000, "Centillion Networks"}
{0x00a001, "DRS Signal Solutions"}
{0x00a002, "Leeds & Northrup Australia"}
{0x00a003, "Siemens Switzerland, I B T HVP"}
{0x00a004, "Netpower"}
{0x00a005, "Daniel Instruments"}
{0x00a006, "Image Data Processing System Group"}
{0x00a007, "Apexx Technology"}
{0x00a008, "Netcorp"}
{0x00a009, "Whitetree Network"}
{0x00a00a, "Airspan"}
{0x00a00b, "Computex CO."}
{0x00a00c, "Kingmax Technology"}
{0x00a00d, "THE Panda Project"}
{0x00a00e, "Visual Networks"}
{0x00a00f, "Broadband Technologies"}
{0x00a010, "Syslogic Datentechnik AG"}
{0x00a011, "Mutoh Industries"}
{0x00a012, "Telco Systems"}
{0x00a013, "Teltrend"}
{0x00a014, "Csir"}
{0x00a015, "Wyle"}
{0x00a016, "Micropolis"}
{0x00a017, "J B"}
{0x00a018, "Creative Controllers"}
{0x00a019, "Nebula Consultants"}
{0x00a01a, "Binar Elektronik AB"}
{0x00a01b, "Premisys Communications"}
{0x00a01c, "Nascent Networks"}
{0x00a01d, "Sixnet"}
{0x00a01e, "EST"}
{0x00a01f, "Tricord Systems"}
{0x00a020, "Citicorp/tti"}
{0x00a021, "General Dynamics"}
{0x00a022, "Centre FOR Development OF Advanced Computing"}
{0x00a023, "Applied Creative Technology"}
{0x00a024, "3com"}
{0x00a025, "Redcom Labs"}
{0x00a026, "Teldat"}
{0x00a027, "Firepower Systems"}
{0x00a028, "Conner Peripherals"}
{0x00a029, "Coulter"}
{0x00a02a, "Trancell Systems"}
{0x00a02b, "Transitions Research"}
{0x00a02c, "interWAVE Communications"}
{0x00a02d, "1394 Trade Association"}
{0x00a02e, "Brand Communications"}
{0x00a02f, "Pirelli Cavi"}
{0x00a030, "Captor Nv/sa"}
{0x00a031, "Hazeltine, MS 1-17"}
{0x00a032, "GES Singapore PTE."}
{0x00a033, "imc MeBsysteme GmbH"}
{0x00a034, "Axel"}
{0x00a035, "Cylink"}
{0x00a036, "Applied Network Technology"}
{0x00a037, "Mindray DS USA"}
{0x00a038, "Email Electronics"}
{0x00a039, "Ross Technology"}
{0x00a03a, "Kubotek"}
{0x00a03b, "Toshin Electric CO."}
{0x00a03c, "Eg&g Nuclear Instruments"}
{0x00a03d, "Opto-22"}
{0x00a03e, "ATM Forum"}
{0x00a03f, "Computer Society Microprocessor & Microprocessor Standards"}
{0x00a040, "Apple Computer"}
{0x00a041, "Inficon"}
{0x00a042, "Spur Products"}
{0x00a043, "American Technology LABS"}
{0x00a044, "NTT IT CO."}
{0x00a045, "Phoenix Contact Gmbh & CO."}
{0x00a046, "Scitex"}
{0x00a047, "Integrated Fitness"}
{0x00a048, "Questech"}
{0x00a049, "Digitech Industries"}
{0x00a04a, "Nisshin Electric CO."}
{0x00a04b, "TFL LAN"}
{0x00a04c, "Innovative Systems & Technologies"}
{0x00a04d, "EDA Instruments"}
{0x00a04e, "Voelker Technologies"}
{0x00a04f, "Ameritec"}
{0x00a050, "Cypress Semiconductor"}
{0x00a051, "Angia Communications."}
{0x00a052, "Stanilite Electronics"}
{0x00a053, "Compact Devices"}
{0x00a054, "Private"}
{0x00a055, "Data Device"}
{0x00a056, "Micropross"}
{0x00a057, "Lancom Systems Gmbh"}
{0x00a058, "Glory"}
{0x00a059, "Hamilton Hallmark"}
{0x00a05a, "Kofax Image Products"}
{0x00a05b, "Marquip"}
{0x00a05c, "Inventory Conversion"}
{0x00a05d, "CS Computer Systeme Gmbh"}
{0x00a05e, "Myriad Logic"}
{0x00a05f, "BTG Electronics Design BV"}
{0x00a060, "Acer Peripherals"}
{0x00a061, "Puritan Bennett"}
{0x00a062, "AES Prodata"}
{0x00a063, "JRL Systems"}
{0x00a064, "Kvb/analect"}
{0x00a065, "Symantec"}
{0x00a066, "ISA CO."}
{0x00a067, "Network Services Group"}
{0x00a068, "BHP Limited"}
{0x00a069, "Symmetricom"}
{0x00a06a, "Verilink"}
{0x00a06b, "DMS Dorsch Mikrosystem Gmbh"}
{0x00a06c, "Shindengen Electric MFG. CO."}
{0x00a06d, "Mannesmann Tally"}
{0x00a06e, "Austron"}
{0x00a06f, "THE Appcon Group"}
{0x00a070, "Coastcom"}
{0x00a071, "Video Lottery Technologies"}
{0x00a072, "Ovation Systems"}
{0x00a073, "Com21"}
{0x00a074, "Perception Technology"}
{0x00a075, "Micron Technology"}
{0x00a076, "Cardware LAB"}
{0x00a077, "Fujitsu Nexion"}
{0x00a078, "Marconi Communications"}
{0x00a079, "Alps Electric (usa)"}
{0x00a07a, "Advanced Peripherals Technologies"}
{0x00a07b, "Dawn Computer Incorporation"}
{0x00a07c, "Tonyang Nylon CO."}
{0x00a07d, "Seeq Technology"}
{0x00a07e, "Avid Technology"}
{0x00a07f, "Gsm-syntel"}
{0x00a080, "SBE"}
{0x00a081, "Alcatel Data Networks"}
{0x00a082, "NKT Elektronik A/S"}
{0x00a083, "Asimmphony Turkey"}
{0x00a084, "Dataplex"}
{0x00a085, "Private"}
{0x00a086, "Amber Wave Systems"}
{0x00a087, "Zarlink Semiconductor"}
{0x00a088, "Essential Communications"}
{0x00a089, "Xpoint Technologies"}
{0x00a08a, "Brooktrout Technology"}
{0x00a08b, "Aston Electronic Designs"}
{0x00a08c, "MultiMedia LANs"}
{0x00a08d, "Jacomo"}
{0x00a08e, "Check Point Software Technologies"}
{0x00a08f, "Desknet Systems"}
{0x00a090, "TimeStep"}
{0x00a091, "Applicom International"}
{0x00a092, "H. Bollmann Manufacturers"}
{0x00a093, "B/E Aerospace"}
{0x00a094, "Comsat"}
{0x00a095, "Acacia Networks"}
{0x00a096, "Mitumi Electric CO."}
{0x00a097, "JC Information Systems"}
{0x00a098, "NetApp"}
{0x00a099, "K-net"}
{0x00a09a, "Nihon Kohden America"}
{0x00a09b, "Qpsx Communications"}
{0x00a09c, "Xyplex"}
{0x00a09d, "Johnathon Freeman Technologies"}
{0x00a09e, "Ictv"}
{0x00a09f, "Commvision"}
{0x00a0a0, "Compact DATA"}
{0x00a0a1, "Epic Data"}
{0x00a0a2, "Digicom S.p.a."}
{0x00a0a3, "Reliable Power Meters"}
{0x00a0a4, "Micros Systems"}
{0x00a0a5, "Teknor Microsysteme"}
{0x00a0a6, "M.I. Systems"}
{0x00a0a7, "Vorax"}
{0x00a0a8, "Renex"}
{0x00a0a9, "Navtel Communications"}
{0x00a0aa, "Spacelabs Medical"}
{0x00a0ab, "Netcs Informationstechnik Gmbh"}
{0x00a0ac, "Gilat Satellite Networks"}
{0x00a0ad, "Marconi SPA"}
{0x00a0ae, "Nucom Systems"}
{0x00a0af, "WMS Industries"}
{0x00a0b0, "I-O Data Device"}
{0x00a0b1, "First Virtual"}
{0x00a0b2, "Shima Seiki"}
{0x00a0b3, "Zykronix"}
{0x00a0b4, "Texas Microsystems"}
{0x00a0b5, "3H Technology"}
{0x00a0b6, "Sanritz Automation CO."}
{0x00a0b7, "Cordant"}
{0x00a0b8, "Symbios Logic"}
{0x00a0b9, "Eagle Technology"}
{0x00a0ba, "Patton Electronics CO."}
{0x00a0bb, "Hilan Gmbh"}
{0x00a0bc, "Viasat, Incorporated"}
{0x00a0bd, "I-tech"}
{0x00a0be, "Integrated Circuit Systems, Communications Group"}
{0x00a0bf, "Wireless Data Group Motorola"}
{0x00a0c0, "Digital Link"}
{0x00a0c1, "Ortivus Medical AB"}
{0x00a0c2, "R.A. Systems CO."}
{0x00a0c3, "Unicomputer Gmbh"}
{0x00a0c4, "Cristie Electronics"}
{0x00a0c5, "Zyxel Communication"}
{0x00a0c6, "Qualcomm Incorporated"}
{0x00a0c7, "Tadiran Telecommunications"}
{0x00a0c8, "Adtran"}
{0x00a0c9, "Intel - Hf1-06"}
{0x00a0ca, "Fujitsu Denso"}
{0x00a0cb, "ARK Telecommunications"}
{0x00a0cc, "Lite-on Communications"}
{0x00a0cd, "DR. Johannes Heidenhain Gmbh"}
{0x00a0ce, "Ecessa"}
{0x00a0cf, "Sotas"}
{0x00a0d0, "TEN X Technology"}
{0x00a0d1, "Inventec"}
{0x00a0d2, "Allied Telesis International"}
{0x00a0d3, "Instem Computer Systems"}
{0x00a0d4, "Radiolan"}
{0x00a0d5, "Sierra Wireless"}
{0x00a0d6, "SBE"}
{0x00a0d7, "Kasten Chase Applied Research"}
{0x00a0d8, "Spectra - TEK"}
{0x00a0d9, "Convex Computer"}
{0x00a0da, "Integrated Systems Technology"}
{0x00a0db, "Fisher & Paykel Production"}
{0x00a0dc, "O.N. Electronic CO."}
{0x00a0dd, "Azonix"}
{0x00a0de, "Yamaha"}
{0x00a0df, "STS Technologies"}
{0x00a0e0, "Tennyson Technologies"}
{0x00a0e1, "Westport Research Associates"}
{0x00a0e2, "Keisokugiken"}
{0x00a0e3, "XKL Systems"}
{0x00a0e4, "Optiquest"}
{0x00a0e5, "NHC Communications"}
{0x00a0e6, "Dialogic"}
{0x00a0e7, "Central Data"}
{0x00a0e8, "Reuters Holdings PLC"}
{0x00a0e9, "Electronic Retailing Systems International"}
{0x00a0ea, "Ethercom"}
{0x00a0eb, "Encore Networks"}
{0x00a0ec, "Transmitton"}
{0x00a0ed, "Brooks Automation"}
{0x00a0ee, "Nashoba Networks"}
{0x00a0ef, "Lucidata"}
{0x00a0f0, "Toronto Microelectronics"}
{0x00a0f1, "MTI"}
{0x00a0f2, "Infotek Communications"}
{0x00a0f3, "Staubli"}
{0x00a0f4, "GE"}
{0x00a0f5, "Radguard"}
{0x00a0f6, "AutoGas Systems"}
{0x00a0f7, "V.I Computer"}
{0x00a0f8, "Symbol Technologies"}
{0x00a0f9, "Bintec Communications Gmbh"}
{0x00a0fa, "Marconi Communication GmbH"}
{0x00a0fb, "Toray Engineering CO."}
{0x00a0fc, "Image Sciences"}
{0x00a0fd, "Scitex Digital Printing"}
{0x00a0fe, "Boston Technology"}
{0x00a0ff, "Tellabs Operations"}
{0x00a1de, "ShenZhen ShiHua Technology CO."}
{0x00a2da, "Inat Gmbh"}
{0x00aa00, "Intel"}
{0x00aa01, "Intel"}
{0x00aa02, "Intel"}
{0x00aa3c, "Olivetti Telecom SPA (olteco)"}
{0x00aa70, "LG Electronics "}
{0x00b009, "Grass Valley Group"}
{0x00b017, "InfoGear Technology"}
{0x00b019, "Casi-Rusco"}
{0x00b01c, "Westport Technologies"}
{0x00b01e, "Rantic Labs"}
{0x00b02a, "Orsys Gmbh"}
{0x00b02d, "ViaGate Technologies"}
{0x00b033, "OAO "Izhevskiy radiozavod""}
{0x00b03b, "HiQ Networks"}
{0x00b048, "Marconi Communications"}
{0x00b04a, "Cisco Systems"}
{0x00b052, "Atheros Communications"}
{0x00b064, "Cisco Systems"}
{0x00b069, "Honewell Oy"}
{0x00b06d, "Jones Futurex"}
{0x00b080, "Mannesmann Ipulsys B.V."}
{0x00b086, "LocSoft Limited"}
{0x00b08e, "Cisco Systems"}
{0x00b091, "Transmeta"}
{0x00b094, "Alaris"}
{0x00b09a, "Morrow Technologies"}
{0x00b09d, "Point Grey Research"}
{0x00b0ac, "Siae-microelettronica S.p.a."}
{0x00b0ae, "Symmetricom"}
{0x00b0b3, "Xstreamis PLC"}
{0x00b0c2, "Cisco Systems"}
{0x00b0c7, "Tellabs Operations"}
{0x00b0ce, "Technology Rescue"}
{0x00b0d0, "Dell Computer"}
{0x00b0db, "Nextcell"}
{0x00b0df, "Reldata"}
{0x00b0e7, "British Federal"}
{0x00b0ec, "Eacem"}
{0x00b0ee, "Ajile Systems"}
{0x00b0f0, "Caly Networks"}
{0x00b0f5, "NetWorth Technologies"}
{0x00b338, "Kontron Design Manufacturing Services (M) Sdn. Bhd"}
{0x00b342, "MacroSAN Technologies Co."}
{0x00b5d6, "Omnibit"}
{0x00b9f6, "Shenzhen Super Rich Electronics Co."}
{0x00bac0, "Biometric Access Company"}
{0x00bb01, "Octothorpe"}
{0x00bb8e, "HME Co."}
{0x00bbf0, "Ungermann-bass"}
{0x00bd27, "Exar"}
{0x00bd3a, "Nokia"}
{0x00c000, "Lanoptics"}
{0x00c001, "Diatek Patient Managment"}
{0x00c002, "Sercomm"}
{0x00c003, "Globalnet Communications"}
{0x00c004, "Japan Business Computerltd"}
{0x00c005, "Livingston Enterprises"}
{0x00c006, "Nippon Avionics CO."}
{0x00c007, "Pinnacle Data Systems"}
{0x00c008, "Seco SRL"}
{0x00c009, "KT Technology (S) PTE"}
{0x00c00a, "Micro Craft"}
{0x00c00b, "Norcontrol A.S."}
{0x00c00c, "Relia Technolgies"}
{0x00c00d, "Advanced Logic Research"}
{0x00c00e, "Psitech"}
{0x00c00f, "Quantum Software Systems"}
{0x00c010, "Hirakawa Hewtech"}
{0x00c011, "Interactive Computing Devices"}
{0x00c012, "Netspan"}
{0x00c013, "Netrix"}
{0x00c014, "Telematics Calabasas Int'l"}
{0x00c015, "NEW Media"}
{0x00c016, "Electronic Theatre Controls"}
{0x00c017, "Fluke"}
{0x00c018, "Lanart"}
{0x00c019, "Leap Technology"}
{0x00c01a, "Corometrics Medical Systems"}
{0x00c01b, "Socket Communications"}
{0x00c01c, "Interlink Communications"}
{0x00c01d, "Grand Junction Networks"}
{0x00c01e, "LA Francaise DES Jeux"}
{0x00c01f, "S.e.r.c.e.l."}
{0x00c020, "Arco Electronic, Control"}
{0x00c021, "Netexpress"}
{0x00c022, "Lasermaster Technologies"}
{0x00c023, "Tutankhamon Electronics"}
{0x00c024, "Eden Sistemas DE Computacao SA"}
{0x00c025, "Dataproducts"}
{0x00c026, "Lans Technology CO."}
{0x00c027, "Cipher Systems"}
{0x00c028, "Jasco"}
{0x00c029, "Nexans Deutschland GmbH - ANS"}
{0x00c02a, "Ohkura Electric CO."}
{0x00c02b, "Gerloff Gesellschaft FUR"}
{0x00c02c, "Centrum Communications"}
{0x00c02d, "Fuji Photo Film CO."}
{0x00c02e, "Netwiz"}
{0x00c02f, "Okuma"}
{0x00c030, "Integrated Engineering B. V."}
{0x00c031, "Design Research Systems"}
{0x00c032, "I-cubed Limited"}
{0x00c033, "Telebit Communications APS"}
{0x00c034, "Transaction Network"}
{0x00c035, "Quintar Company"}
{0x00c036, "Raytech Electronic"}
{0x00c037, "Dynatem"}
{0x00c038, "Raster Image Processing System"}
{0x00c039, "Teridian Semiconductor"}
{0x00c03a, "Men-mikro Elektronik Gmbh"}
{0x00c03b, "Multiaccess Computing"}
{0x00c03c, "Tower Tech S.r.l."}
{0x00c03d, "Wiesemann & Theis Gmbh"}
{0x00c03e, "FA. GEBR. Heller Gmbh"}
{0x00c03f, "Stores Automated Systems"}
{0x00c040, "Ecci"}
{0x00c041, "Digital Transmission Systems"}
{0x00c042, "Datalux"}
{0x00c043, "Stratacom"}
{0x00c044, "Emcom"}
{0x00c045, "Isolation Systems"}
{0x00c046, "Blue Chip Technology"}
{0x00c047, "Unimicro Systems"}
{0x00c048, "BAY Technical Associates"}
{0x00c049, "U.S. Robotics"}
{0x00c04a, "Group 2000 AG"}
{0x00c04b, "Creative Microsystems"}
{0x00c04c, "Department OF Foreign Affairs"}
{0x00c04d, "Mitec"}
{0x00c04e, "Comtrol"}
{0x00c04f, "Dell Computer"}
{0x00c050, "Toyo Denki Seizo K.K."}
{0x00c051, "Advanced Integration Research"}
{0x00c052, "Burr-brown"}
{0x00c053, "Aspect Software"}
{0x00c054, "Network Peripherals"}
{0x00c055, "Modular Computing Technologies"}
{0x00c056, "Somelec"}
{0x00c057, "Myco Electronics"}
{0x00c058, "Dataexpert"}
{0x00c059, "Denso"}
{0x00c05a, "Semaphore Communications"}
{0x00c05b, "Networks Northwest"}
{0x00c05c, "Elonex PLC"}
{0x00c05d, "L&N Technologies"}
{0x00c05e, "Vari-lite"}
{0x00c05f, "Fine-pal Company Limited"}
{0x00c060, "ID Scandinavia AS"}
{0x00c061, "Solectek"}
{0x00c062, "Impulse Technology"}
{0x00c063, "Morning Star Technologies"}
{0x00c064, "General Datacomm IND."}
{0x00c065, "Scope Communications"}
{0x00c066, "Docupoint"}
{0x00c067, "United Barcode Industries"}
{0x00c068, "HME Clear-Com"}
{0x00c069, "Axxcelera Broadband Wireless"}
{0x00c06a, "Zahner-elektrik Gmbh & CO. KG"}
{0x00c06b, "OSI Plus"}
{0x00c06c, "Svec Computer"}
{0x00c06d, "Boca Research"}
{0x00c06e, "Haft Technology"}
{0x00c06f, "Komatsu"}
{0x00c070, "Sectra Secure-transmission AB"}
{0x00c071, "Areanex Communications"}
{0x00c072, "KNX"}
{0x00c073, "Xedia"}
{0x00c074, "Toyoda Automatic Loom"}
{0x00c075, "Xante"}
{0x00c076, "I-data International A-S"}
{0x00c077, "Daewoo Telecom"}
{0x00c078, "Computer Systems Engineering"}
{0x00c079, "Fonsys Co."}
{0x00c07a, "Priva B.V."}
{0x00c07b, "Ascend Communications"}
{0x00c07c, "Hightech Information"}
{0x00c07d, "Risc Developments"}
{0x00c07e, "Kubota Electronic"}
{0x00c07f, "Nupon Computing"}
{0x00c080, "Netstar"}
{0x00c081, "Metrodata"}
{0x00c082, "Moore Products CO."}
{0x00c083, "Trace Mountain Products"}
{0x00c084, "Data Link"}
{0x00c085, "Electronics FOR Imaging"}
{0x00c086, "THE Lynk"}
{0x00c087, "Uunet Technologies"}
{0x00c088, "EKF Elektronik Gmbh"}
{0x00c089, "Telindus Distribution"}
{0x00c08a, "Lauterbach GmbH"}
{0x00c08b, "Risq Modular Systems"}
{0x00c08c, "Performance Technologies"}
{0x00c08d, "Tronix Product Development"}
{0x00c08e, "Network Information Technology"}
{0x00c08f, "Panasonic Electric Works Co."}
{0x00c090, "Praim S.r.l."}
{0x00c091, "Jabil Circuit"}
{0x00c092, "Mennen Medical"}
{0x00c093, "Alta Research"}
{0x00c094, "VMX"}
{0x00c095, "Znyx"}
{0x00c096, "Tamura"}
{0x00c097, "Archipel SA"}
{0x00c098, "Chuntex Electronic CO."}
{0x00c099, "Yoshiki Industrial Co."}
{0x00c09a, "Photonics"}
{0x00c09b, "Reliance Comm/tec"}
{0x00c09c, "Hioki E.E."}
{0x00c09d, "Distributed Systems Int'l"}
{0x00c09e, "Cache Computers"}
{0x00c09f, "Quanta Computer"}
{0x00c0a0, "Advance Micro Research"}
{0x00c0a1, "Tokyo Denshi Sekei CO."}
{0x00c0a2, "Intermedium A/S"}
{0x00c0a3, "Dual Enterprises"}
{0x00c0a4, "Unigraf OY"}
{0x00c0a5, "Dickens Data Systems"}
{0x00c0a6, "Exicom Australia"}
{0x00c0a7, "Seel"}
{0x00c0a8, "GVC"}
{0x00c0a9, "Barron Mccann"}
{0x00c0aa, "Silicon Valley Computer"}
{0x00c0ab, "Telco Systems"}
{0x00c0ac, "Gambit Computer Communications"}
{0x00c0ad, "Marben Communication Systems"}
{0x00c0ae, "Towercom CO. DBA PC House"}
{0x00c0af, "Teklogix"}
{0x00c0b0, "GCC Technologies"}
{0x00c0b1, "Genius NET CO."}
{0x00c0b2, "Norand"}
{0x00c0b3, "Comstat Datacomm"}
{0x00c0b4, "Myson Technology"}
{0x00c0b5, "Corporate Network Systems"}
{0x00c0b6, "Overland Storage"}
{0x00c0b7, "American Power Conversion"}
{0x00c0b8, "Fraser's Hill"}
{0x00c0b9, "Funk Software"}
{0x00c0ba, "Netvantage"}
{0x00c0bb, "Forval Creative"}
{0x00c0bc, "Telecom Australia/cssc"}
{0x00c0bd, "Inex Technologies"}
{0x00c0be, "Alcatel - SEL"}
{0x00c0bf, "Technology Concepts"}
{0x00c0c0, "Shore Microsystems"}
{0x00c0c1, "Quad/graphics"}
{0x00c0c2, "Infinite Networks"}
{0x00c0c3, "Acuson Computed Sonography"}
{0x00c0c4, "Computer Operational"}
{0x00c0c5, "SID Informatica"}
{0x00c0c6, "Personal Media"}
{0x00c0c7, "Sparktrum Microsystems"}
{0x00c0c8, "Micro Byte"}
{0x00c0c9, "Elsag Bailey Process"}
{0x00c0ca, "ALFA"}
{0x00c0cb, "Control Technology"}
{0x00c0cc, "Telesciences CO Systems"}
{0x00c0cd, "Comelta"}
{0x00c0ce, "CEI Systems & Engineering PTE"}
{0x00c0cf, "Imatran Voima OY"}
{0x00c0d0, "Ratoc System"}
{0x00c0d1, "Comtree Technology"}
{0x00c0d2, "Syntellect"}
{0x00c0d3, "Olympus Image Systems"}
{0x00c0d4, "Axon Networks"}
{0x00c0d5, "Werbeagentur Jrgen Siebert"}
{0x00c0d6, "J1 Systems"}
{0x00c0d7, "Taiwan Trading Center DBA"}
{0x00c0d8, "Universal Data Systems"}
{0x00c0d9, "Quinte Network Confidentiality"}
{0x00c0da, "Nice Systems"}
{0x00c0db, "IPC (pte)"}
{0x00c0dc, "EOS Technologies"}
{0x00c0dd, "QLogic"}
{0x00c0de, "Zcomm"}
{0x00c0df, "KYE Systems"}
{0x00c0e0, "DSC Communication"}
{0x00c0e1, "Sonic Solutions"}
{0x00c0e2, "Calcomp"}
{0x00c0e3, "Ositech Communications"}
{0x00c0e4, "Siemens Building"}
{0x00c0e5, "Gespac"}
{0x00c0e6, "Verilink"}
{0x00c0e7, "Fiberdata AB"}
{0x00c0e8, "Plexcom"}
{0x00c0e9, "OAK Solutions"}
{0x00c0ea, "Array Technology"}
{0x00c0eb, "SEH Computertechnik Gmbh"}
{0x00c0ec, "Dauphin Technology"}
{0x00c0ed, "US Army Electronic"}
{0x00c0ee, "Kyocera"}
{0x00c0ef, "Abit"}
{0x00c0f0, "Kingston Technology"}
{0x00c0f1, "Shinko Electric CO."}
{0x00c0f2, "Transition Networks"}
{0x00c0f3, "Network Communications"}
{0x00c0f4, "Interlink System CO."}
{0x00c0f5, "Metacomp"}
{0x00c0f6, "Celan Technology"}
{0x00c0f7, "Engage Communication"}
{0x00c0f8, "About Computing"}
{0x00c0f9, "Emerson Network Power"}
{0x00c0fa, "Canary Communications"}
{0x00c0fb, "Advanced Technology Labs"}
{0x00c0fc, "Elastic Reality"}
{0x00c0fd, "Prosum"}
{0x00c0fe, "Aptec Computer Systems"}
{0x00c0ff, "DOT Hill Systems"}
{0x00c610, "Apple"}
{0x00cbbd, "Cambridge Broadband Networks"}
{0x00cd90, "MAS Elektronik AG"}
{0x00cf1c, "Communication Machinery"}
{0x00d000, "Ferran Scientific"}
{0x00d001, "VST Technologies"}
{0x00d002, "Ditech"}
{0x00d003, "Comda Enterprises"}
{0x00d004, "Pentacom"}
{0x00d005, "ZHS Zeitmanagementsysteme"}
{0x00d006, "Cisco Systems"}
{0x00d007, "MIC Associates"}
{0x00d008, "Mactell"}
{0x00d009, "Hsing TECH. Enterprise CO."}
{0x00d00a, "Lanaccess Telecom S.A."}
{0x00d00b, "RHK Technology"}
{0x00d00c, "Snijder Micro Systems"}
{0x00d00d, "Micromeritics Instrument"}
{0x00d00e, "Pluris"}
{0x00d00f, "Speech Design Gmbh"}
{0x00d010, "Convergent Networks"}
{0x00d011, "Prism Video"}
{0x00d012, "Gateworks"}
{0x00d013, "Primex Aerospace Company"}
{0x00d014, "ROOT"}
{0x00d015, "Univex Microtechnology"}
{0x00d016, "SCM Microsystems"}
{0x00d017, "Syntech Information CO."}
{0x00d018, "QWES. COM"}
{0x00d019, "Dainippon Screen Corporate"}
{0x00d01a, "Urmet  TLC S.p.a."}
{0x00d01b, "Mimaki Engineering CO."}
{0x00d01c, "SBS Technologies,"}
{0x00d01d, "Furuno Electric CO."}
{0x00d01e, "Pingtel"}
{0x00d01f, "Ctam"}
{0x00d020, "AIM System"}
{0x00d021, "Regent Electronics"}
{0x00d022, "Incredible Technologies"}
{0x00d023, "Infortrend Technology"}
{0x00d024, "Cognex"}
{0x00d025, "Xrosstech"}
{0x00d026, "Hirschmann Austria Gmbh"}
{0x00d027, "Applied Automation"}
{0x00d028, "Omneon Video Networks"}
{0x00d029, "Wakefern Food"}
{0x00d02a, "Voxent Systems"}
{0x00d02b, "Jetcell"}
{0x00d02c, "Campbell Scientific"}
{0x00d02d, "Ademco"}
{0x00d02e, "Communication Automation"}
{0x00d02f, "Vlsi Technology"}
{0x00d030, "Safetran Systems"}
{0x00d031, "Industrial Logic"}
{0x00d032, "Yano Electric CO."}
{0x00d033, "Dalian Daxian Network"}
{0x00d034, "Ormec Systems"}
{0x00d035, "Behavior TECH. Computer"}
{0x00d036, "Technology Atlanta"}
{0x00d037, "Pace France"}
{0x00d038, "Fivemere"}
{0x00d039, "Utilicom"}
{0x00d03a, "Zoneworx"}
{0x00d03b, "Vision Products"}
{0x00d03c, "Vieo"}
{0x00d03d, "Galileo Technology"}
{0x00d03e, "Rocketchips"}
{0x00d03f, "American Communication"}
{0x00d040, "Sysmate CO."}
{0x00d041, "Amigo Technology CO."}
{0x00d042, "Mahlo Gmbh & CO. UG"}
{0x00d043, "Zonal Retail Data Systems"}
{0x00d044, "Alidian Networks"}
{0x00d045, "Kvaser AB"}
{0x00d046, "Dolby Laboratories"}
{0x00d047, "XN Technologies"}
{0x00d048, "Ecton"}
{0x00d049, "Impresstek CO."}
{0x00d04a, "Presence Technology Gmbh"}
{0x00d04b, "LA CIE Group S.A."}
{0x00d04c, "Eurotel Telecom"}
{0x00d04d, "DIV OF Research & Statistics"}
{0x00d04e, "Logibag"}
{0x00d04f, "Bitronics"}
{0x00d050, "Iskratel"}
{0x00d051, "O2 Micro"}
{0x00d052, "Ascend Communications"}
{0x00d053, "Connected Systems"}
{0x00d054, "SAS Institute"}
{0x00d055, "Kathrein-werke KG"}
{0x00d056, "Somat"}
{0x00d057, "Ultrak"}
{0x00d058, "Cisco Systems"}
{0x00d059, "Ambit Microsystems"}
{0x00d05a, "Symbionics"}
{0x00d05b, "Acroloop Motion Control"}
{0x00d05c, "Technotrend Systemtechnik Gmbh"}
{0x00d05d, "Intelliworxx"}
{0x00d05e, "Stratabeam Technology"}
{0x00d05f, "Valcom"}
{0x00d060, "Panasonic Europe"}
{0x00d061, "Tremon Enterprises CO."}
{0x00d062, "Digigram"}
{0x00d063, "Cisco Systems"}
{0x00d064, "Multitel"}
{0x00d065, "Toko Electric"}
{0x00d066, "Wintriss Engineering"}
{0x00d067, "Campio Communications"}
{0x00d068, "Iwill"}
{0x00d069, "Technologic Systems"}
{0x00d06a, "Linkup Systems"}
{0x00d06b, "SR Telecom"}
{0x00d06c, "Sharewave"}
{0x00d06d, "Acrison"}
{0x00d06e, "Trendview Recorders"}
{0x00d06f, "KMC Controls"}
{0x00d070, "Long Well Electronics"}
{0x00d071, "Echelon"}
{0x00d072, "Broadlogic"}
{0x00d073, "ACN Advanced Communications"}
{0x00d074, "Taqua Systems"}
{0x00d075, "Alaris Medical Systems"}
{0x00d076, "Bank of America"}
{0x00d077, "Lucent Technologies"}
{0x00d078, "Eltex of Sweden AB"}
{0x00d079, "Cisco Systems"}
{0x00d07a, "Amaquest Computer"}
{0x00d07b, "Comcam International"}
{0x00d07c, "Koyo Electronics Co."}
{0x00d07d, "Cosine Communications"}
{0x00d07e, "Keycorp"}
{0x00d07f, "Strategy & Technology, Limited"}
{0x00d080, "Exabyte"}
{0x00d081, "RTD Embedded Technologies"}
{0x00d082, "Iowave"}
{0x00d083, "Invertex"}
{0x00d084, "Nexcomm Systems"}
{0x00d085, "Otis Elevator Company"}
{0x00d086, "Foveon"}
{0x00d087, "Microfirst"}
{0x00d088, "Motorola"}
{0x00d089, "Dynacolor"}
{0x00d08a, "Photron USA"}
{0x00d08b, "Adva Optical Networking"}
{0x00d08c, "Genoa Technology"}
{0x00d08d, "Phoenix Group"}
{0x00d08e, "Nvision"}
{0x00d08f, "Ardent Technologies"}
{0x00d090, "Cisco Systems"}
{0x00d091, "Smartsan Systems"}
{0x00d092, "Glenayre Western Multiplex"}
{0x00d093, "TQ - Components Gmbh"}
{0x00d094, "Timeline Vista"}
{0x00d095, "Alcatel-Lucent, Enterprise Business Group"}
{0x00d096, "3com Europe"}
{0x00d097, "Cisco Systems"}
{0x00d098, "Photon Dynamics Canada"}
{0x00d099, "Elcard OY"}
{0x00d09a, "Filanet"}
{0x00d09b, "Spectel"}
{0x00d09c, "Kapadia Communications"}
{0x00d09d, "Veris Industries"}
{0x00d09e, "2wire"}
{0x00d09f, "Novtek Test Systems"}
{0x00d0a0, "Mips Denmark"}
{0x00d0a1, "Oskar Vierling Gmbh + CO. KG"}
{0x00d0a2, "Integrated Device"}
{0x00d0a3, "Vocal DATA"}
{0x00d0a4, "Alantro Communications"}
{0x00d0a5, "American Arium"}
{0x00d0a6, "Lanbird Technology CO."}
{0x00d0a7, "Tokyo Sokki Kenkyujo CO."}
{0x00d0a8, "Network Engines"}
{0x00d0a9, "Shinano Kenshi CO."}
{0x00d0aa, "Chase Communications"}
{0x00d0ab, "Deltakabel Telecom CV"}
{0x00d0ac, "Grayson Wireless"}
{0x00d0ad, "TL Industries"}
{0x00d0ae, "Oresis Communications"}
{0x00d0af, "Cutler-hammer"}
{0x00d0b0, "Bitswitch"}
{0x00d0b1, "Omega Electronics SA"}
{0x00d0b2, "Xiotech"}
{0x00d0b3, "DRS Flight Safety AND"}
{0x00d0b4, "Katsujima CO."}
{0x00d0b5, "IPricot formerly DotCom"}
{0x00d0b6, "Crescent Networks"}
{0x00d0b7, "Intel"}
{0x00d0b8, "Iomega"}
{0x00d0b9, "Microtek International"}
{0x00d0ba, "Cisco Systems"}
{0x00d0bb, "Cisco Systems"}
{0x00d0bc, "Cisco Systems"}
{0x00d0bd, "Silicon Image GmbH"}
{0x00d0be, "Emutec"}
{0x00d0bf, "Pivotal Technologies"}
{0x00d0c0, "Cisco Systems"}
{0x00d0c1, "Harmonic Data Systems"}
{0x00d0c2, "Balthazar Technology AB"}
{0x00d0c3, "Vivid Technology PTE"}
{0x00d0c4, "Teratech"}
{0x00d0c5, "Computational Systems"}
{0x00d0c6, "Thomas & Betts"}
{0x00d0c7, "Pathway"}
{0x00d0c8, "Prevas A/S"}
{0x00d0c9, "Advantech CO."}
{0x00d0ca, "Intrinsyc Software International"}
{0x00d0cb, "Dasan CO."}
{0x00d0cc, "Technologies Lyre"}
{0x00d0cd, "Atan Technology"}
{0x00d0ce, "Asyst Electronic"}
{0x00d0cf, "Moreton BAY"}
{0x00d0d0, "Zhongxing Telecom"}
{0x00d0d1, "Sycamore Networks"}
{0x00d0d2, "Epilog"}
{0x00d0d3, "Cisco Systems"}
{0x00d0d4, "V-bits"}
{0x00d0d5, "Grundig AG"}
{0x00d0d6, "Aethra Telecomunicazioni"}
{0x00d0d7, "B2C2"}
{0x00d0d8, "3Com"}
{0x00d0d9, "Dedicated Microcomputers"}
{0x00d0da, "Taicom Data Systems CO."}
{0x00d0db, "Mcquay International"}
{0x00d0dc, "Modular Mining Systems"}
{0x00d0dd, "Sunrise Telecom"}
{0x00d0de, "Philips Multimedia Network"}
{0x00d0df, "Kuzumi Electronics"}
{0x00d0e0, "Dooin Electronics CO."}
{0x00d0e1, "Avionitek Israel"}
{0x00d0e2, "MRT Micro"}
{0x00d0e3, "Ele-chem Engineering CO."}
{0x00d0e4, "Cisco Systems"}
{0x00d0e5, "Solidum Systems"}
{0x00d0e6, "Ibond"}
{0x00d0e7, "Vcon Telecommunication"}
{0x00d0e8, "MAC System CO."}
{0x00d0e9, "Advantage Century Telecommunication"}
{0x00d0ea, "Nextone Communications"}
{0x00d0eb, "Lightera Networks"}
{0x00d0ec, "Nakayo Telecommunications"}
{0x00d0ed, "Xiox"}
{0x00d0ee, "Dictaphone"}
{0x00d0ef, "IGT"}
{0x00d0f0, "Convision Technology Gmbh"}
{0x00d0f1, "Sega Enterprises"}
{0x00d0f2, "Monterey Networks"}
{0x00d0f3, "Solari DI Udine SPA"}
{0x00d0f4, "Carinthian Tech Institute"}
{0x00d0f5, "Orange Micro"}
{0x00d0f6, "Alcatel Canada"}
{0x00d0f7, "Next Nets"}
{0x00d0f8, "Fujian Star Terminal"}
{0x00d0f9, "Acute Communications"}
{0x00d0fa, "Thales e-Security"}
{0x00d0fb, "TEK Microsystems, Incorporated"}
{0x00d0fc, "Granite Microsystems"}
{0x00d0fd, "Optima Tele.com"}
{0x00d0fe, "Astral Point"}
{0x00d0ff, "Cisco Systems"}
{0x00d11c, "Acetel"}
{0x00d38d, "Hotel Technology Next Generation"}
{0x00d632, "GE Energy"}
{0x00db45, "Thamway Co."}
{0x00dbdf, "Intel Corporate"}
{0x00dd00, "Ungermann-bass"}
{0x00dd01, "Ungermann-bass"}
{0x00dd02, "Ungermann-bass"}
{0x00dd03, "Ungermann-bass"}
{0x00dd04, "Ungermann-bass"}
{0x00dd05, "Ungermann-bass"}
{0x00dd06, "Ungermann-bass"}
{0x00dd07, "Ungermann-bass"}
{0x00dd08, "Ungermann-bass"}
{0x00dd09, "Ungermann-bass"}
{0x00dd0a, "Ungermann-bass"}
{0x00dd0b, "Ungermann-bass"}
{0x00dd0c, "Ungermann-bass"}
{0x00dd0d, "Ungermann-bass"}
{0x00dd0e, "Ungermann-bass"}
{0x00dd0f, "Ungermann-bass"}
{0x00defb, "Cisco Systems"}
{0x00e000, "Fujitsu Limited"}
{0x00e001, "Strand Lighting Limited"}
{0x00e002, "Crossroads Systems"}
{0x00e003, "Nokia Wireless Business Commun"}
{0x00e004, "Pmc-sierra"}
{0x00e005, "Technical"}
{0x00e006, "Silicon Integrated SYS."}
{0x00e007, "Avaya ECS"}
{0x00e008, "Amazing Controls!"}
{0x00e009, "Marathon Technologies"}
{0x00e00a, "DIBA"}
{0x00e00b, "Rooftop Communications"}
{0x00e00c, "Motorola"}
{0x00e00d, "Radiant Systems"}
{0x00e00e, "Avalon Imaging Systems"}
{0x00e00f, "Shanghai Baud Data"}
{0x00e010, "Hess Sb-automatenbau Gmbh"}
{0x00e011, "Uniden"}
{0x00e012, "Pluto Technologies International"}
{0x00e013, "Eastern Electronic CO."}
{0x00e014, "Cisco Systems"}
{0x00e015, "Heiwa"}
{0x00e016, "Rapid City Communications"}
{0x00e017, "Exxact Gmbh"}
{0x00e018, "Asustek Computer"}
{0x00e019, "ING. Giordano Elettronica"}
{0x00e01a, "Comtec Systems. CO."}
{0x00e01b, "Sphere Communications"}
{0x00e01c, "Cradlepoint"}
{0x00e01d, "Webtv Networks"}
{0x00e01e, "Cisco Systems"}
{0x00e01f, "Avidia Systems"}
{0x00e020, "Tecnomen OY"}
{0x00e021, "Freegate"}
{0x00e022, "Analog Devices"}
{0x00e023, "Telrad"}
{0x00e024, "Gadzoox Networks"}
{0x00e025, "dit Co."}
{0x00e026, "Redlake Masd"}
{0x00e027, "DUX"}
{0x00e028, "Aptix"}
{0x00e029, "Standard Microsystems"}
{0x00e02a, "Tandberg Television AS"}
{0x00e02b, "Extreme Networks"}
{0x00e02c, "AST Computer"}
{0x00e02d, "InnoMediaLogic"}
{0x00e02e, "SPC Electronics"}
{0x00e02f, "Mcns Holdings"}
{0x00e030, "Melita International"}
{0x00e031, "Hagiwara Electric CO."}
{0x00e032, "Misys Financial Systems"}
{0x00e033, "E.E.P.D. GmbH"}
{0x00e034, "Cisco Systems"}
{0x00e035, "Emerson Network Power"}
{0x00e036, "Pioneer"}
{0x00e037, "Century"}
{0x00e038, "Proxima"}
{0x00e039, "Paradyne"}
{0x00e03a, "Cabletron Systems"}
{0x00e03b, "Prominet"}
{0x00e03c, "AdvanSys"}
{0x00e03d, "Focon Electronic Systems A/S"}
{0x00e03e, "Alfatech"}
{0x00e03f, "Jaton"}
{0x00e040, "DeskStation Technology"}
{0x00e041, "Cspi"}
{0x00e042, "Pacom Systems"}
{0x00e043, "VitalCom"}
{0x00e044, "Lsics"}
{0x00e045, "Touchwave"}
{0x00e046, "Bently Nevada"}
{0x00e047, "InFocus"}
{0x00e048, "SDL Communications"}
{0x00e049, "Microwi Electronic Gmbh"}
{0x00e04a, "Enhanced Messaging Systems"}
{0x00e04b, "Jump Industrielle Computertechnik Gmbh"}
{0x00e04c, "Realtek Semiconductor"}
{0x00e04d, "Internet Initiative Japan"}
{0x00e04e, "Sanyo Denki CO."}
{0x00e04f, "Cisco Systems"}
{0x00e050, "Executone Information Systems"}
{0x00e051, "Talx"}
{0x00e052, "Brocade Communications Systems"}
{0x00e053, "Cellport LABS"}
{0x00e054, "Kodai Hitec CO."}
{0x00e055, "Ingenieria Electronica Comercial Inelcom S.A."}
{0x00e056, "Holontech"}
{0x00e057, "HAN Microtelecom. CO."}
{0x00e058, "Phase ONE Denmark A/S"}
{0x00e059, "Controlled Environments"}
{0x00e05a, "Galea Network Security"}
{0x00e05b, "West END Systems"}
{0x00e05c, "Matsushita Kotobuki Electronics Industries"}
{0x00e05d, "Unitec CO."}
{0x00e05e, "Japan Aviation Electronics Industry"}
{0x00e05f, "e-Net"}
{0x00e060, "Sherwood"}
{0x00e061, "EdgePoint Networks"}
{0x00e062, "Host Engineering"}
{0x00e063, "Cabletron - Yago Systems"}
{0x00e064, "Samsung Electronics"}
{0x00e065, "Optical Access International"}
{0x00e066, "ProMax Systems"}
{0x00e067, "eac Automation-consulting Gmbh"}
{0x00e068, "Merrimac Systems"}
{0x00e069, "Jaycor"}
{0x00e06a, "Kapsch AG"}
{0x00e06b, "W&G Special Products"}
{0x00e06c, "AEP Systems International"}
{0x00e06d, "Compuware"}
{0x00e06e, "FAR Systems S.p.a."}
{0x00e06f, "Motorola"}
{0x00e070, "DH Technology"}
{0x00e071, "Epis Microcomputer"}
{0x00e072, "Lynk"}
{0x00e073, "National Amusement Network"}
{0x00e074, "Tiernan Communications"}
{0x00e075, "Verilink"}
{0x00e076, "Development Concepts"}
{0x00e077, "Webgear"}
{0x00e078, "Berkeley Networks"}
{0x00e079, "A.t.n.r."}
{0x00e07a, "Mikrodidakt AB"}
{0x00e07b, "BAY Networks"}
{0x00e07c, "Mettler-toledo"}
{0x00e07d, "Netronix"}
{0x00e07e, "Walt Disney Imagineering"}
{0x00e07f, "Logististem S.r.l."}
{0x00e080, "Control Resources"}
{0x00e081, "Tyan Computer"}
{0x00e082, "Anerma"}
{0x00e083, "Jato Technologies"}
{0x00e084, "Compulite R&D"}
{0x00e085, "Global Maintech"}
{0x00e086, "Cybex Computer Products"}
{0x00e087, "LeCroy - Networking Productions Division"}
{0x00e088, "LTX"}
{0x00e089, "ION Networks"}
{0x00e08a, "GEC Avery"}
{0x00e08b, "QLogic"}
{0x00e08c, "Neoparadigm LABS"}
{0x00e08d, "Pressure Systems"}
{0x00e08e, "Utstarcom"}
{0x00e08f, "Cisco Systems"}
{0x00e090, "Beckman LAB. Automation DIV."}
{0x00e091, "LG Electronics"}
{0x00e092, "Admtek Incorporated"}
{0x00e093, "Ackfin Networks"}
{0x00e094, "Osai SRL"}
{0x00e095, "Advanced-vision Technolgies"}
{0x00e096, "Shimadzu"}
{0x00e097, "Carrier Access"}
{0x00e098, "AboCom Systems"}
{0x00e099, "Samson AG"}
{0x00e09a, "Positron"}
{0x00e09b, "Engage Networks"}
{0x00e09c, "MII"}
{0x00e09d, "Sarnoff"}
{0x00e09e, "Quantum"}
{0x00e09f, "Pixel Vision"}
{0x00e0a0, "Wiltron CO."}
{0x00e0a1, "Hima Paul Hildebrandt Gmbh Co. KG"}
{0x00e0a2, "Microslate"}
{0x00e0a3, "Cisco Systems"}
{0x00e0a4, "Esaote S.p.a."}
{0x00e0a5, "ComCore Semiconductor"}
{0x00e0a6, "Telogy Networks"}
{0x00e0a7, "IPC Information Systems"}
{0x00e0a8, "SAT GmbH & Co."}
{0x00e0a9, "Funai Electric CO."}
{0x00e0aa, "Electrosonic"}
{0x00e0ab, "Dimat S.A."}
{0x00e0ac, "Midsco"}
{0x00e0ad, "EES Technology"}
{0x00e0ae, "Xaqti"}
{0x00e0af, "General Dynamics Information Systems"}
{0x00e0b0, "Cisco Systems"}
{0x00e0b1, "Alcatel-Lucent, Enterprise Business Group"}
{0x00e0b2, "Telmax Communications"}
{0x00e0b3, "EtherWAN Systems"}
{0x00e0b4, "Techno Scope CO."}
{0x00e0b5, "Ardent Communications"}
{0x00e0b6, "Entrada Networks"}
{0x00e0b7, "PI Group"}
{0x00e0b8, "Gateway 2000"}
{0x00e0b9, "Byas Systems"}
{0x00e0ba, "Berghof Automationstechnik Gmbh"}
{0x00e0bb, "NBX"}
{0x00e0bc, "Symon Communications"}
{0x00e0bd, "Interface Systems"}
{0x00e0be, "Genroco International"}
{0x00e0bf, "Torrent Networking Technologies"}
{0x00e0c0, "Seiwa Electric MFG. CO."}
{0x00e0c1, "Memorex Telex Japan"}
{0x00e0c2, "Necsy S.p.a."}
{0x00e0c3, "Sakai System Development"}
{0x00e0c4, "Horner Electric"}
{0x00e0c5, "Bcom Electronics"}
{0x00e0c6, "Link2it, L.l.c."}
{0x00e0c7, "Eurotech SRL"}
{0x00e0c8, "Virtual Access"}
{0x00e0c9, "AutomatedLogic"}
{0x00e0ca, "Best Data Products"}
{0x00e0cb, "Reson"}
{0x00e0cc, "Hero Systems"}
{0x00e0cd, "Sensis"}
{0x00e0ce, "ARN"}
{0x00e0cf, "Integrated Device Technology"}
{0x00e0d0, "Netspeed"}
{0x00e0d1, "Telsis Limited"}
{0x00e0d2, "Versanet Communications"}
{0x00e0d3, "Datentechnik Gmbh"}
{0x00e0d4, "Excellent Computer"}
{0x00e0d5, "Emulex"}
{0x00e0d6, "Computer & Communication Research LAB."}
{0x00e0d7, "Sunshine Electronics"}
{0x00e0d8, "Lanbit Computer"}
{0x00e0d9, "Tazmo CO."}
{0x00e0da, "Alcatel North America ESD"}
{0x00e0db, "ViaVideo Communications"}
{0x00e0dc, "Nexware"}
{0x00e0dd, "Zenith Electronics"}
{0x00e0de, "Datax NV"}
{0x00e0df, "Keymile Gmbh"}
{0x00e0e0, "SI Electronics"}
{0x00e0e1, "G2 Networks"}
{0x00e0e2, "Innova"}
{0x00e0e3, "Sk-elektronik Gmbh"}
{0x00e0e4, "Fanuc Robotics North America"}
{0x00e0e5, "Cinco Networks"}
{0x00e0e6, "Incaa Datacom B.V."}
{0x00e0e7, "Raytheon E-systems"}
{0x00e0e8, "Gretacoder Data Systems AG"}
{0x00e0e9, "Data LABS"}
{0x00e0ea, "Innovat Communications"}
{0x00e0eb, "Digicom Systems, Incorporated"}
{0x00e0ec, "Celestica"}
{0x00e0ed, "Silicom"}
{0x00e0ee, "Marel HF"}
{0x00e0ef, "Dionex"}
{0x00e0f0, "Abler Technology"}
{0x00e0f1, "That"}
{0x00e0f2, "Arlotto Comnet"}
{0x00e0f3, "WebSprint Communications"}
{0x00e0f4, "Inside Technology A/S"}
{0x00e0f5, "Teles AG"}
{0x00e0f6, "Decision Europe"}
{0x00e0f7, "Cisco Systems"}
{0x00e0f8, "Dicna Control AB"}
{0x00e0f9, "Cisco Systems"}
{0x00e0fa, "TRL Technology"}
{0x00e0fb, "Leightronix"}
{0x00e0fc, "Huawei Technologies CO."}
{0x00e0fd, "A-trend Technology CO."}
{0x00e0fe, "Cisco Systems"}
{0x00e0ff, "Security Dynamics Technologies"}
{0x00e175, "AK-Systems"}
{0x00e6d3, "Nixdorf Computer"}
{0x00f051, "KWB Gmbh"}
{0x00f4b9, "Apple"}
{0x00f860, "PT. Panggung Electric Citrabuana"}
{0x00fa3b, "Cloos Electronic Gmbh"}
{0x00fc58, "WebSilicon"}
{0x00fc70, "Intrepid Control Systems"}
{0x020701, "Racal-datacom"}
{0x021c7c, "Perq Systems"}
{0x026086, "Logic Replacement TECH."}
{0x02608c, "3com"}
{0x027001, "Racal-datacom"}
{0x0270b0, "M/a-com Companies"}
{0x0270b3, "Data Recall"}
{0x029d8e, "Cardiac Recorders"}
{0x02aa3c, "Olivetti Telecomm SPA (olteco)"}
{0x02bb01, "Octothorpe"}
{0x02c08c, "3com"}
{0x02cf1c, "Communication Machinery"}
{0x02e6d3, "Nixdorf Computer"}
{0x040a83, "Alcatel-Lucent"}
{0x040ae0, "Xmit AG Computer Networks"}
{0x040cce, "Apple"}
{0x040ec2, "ViewSonic Mobile China Limited"}
{0x04180f, "Samsung Electronics Co."}
{0x0418b6, "Private"}
{0x041d10, "Dream Ware"}
{0x041e64, "Apple"}
{0x04209a, "Panasonic AVC Networks Company"}
{0x042234, "Wireless Standard Extensions"}
{0x042605, "GFR Gesellschaft fr Regelungstechnik und Energieeinsparung mbH"}
{0x042bbb, "PicoCELA"}
{0x042f56, "Atocs (shenzhen)"}
{0x0432f4, "Partron"}
{0x043604, "Gyeyoung I&T"}
{0x044665, "Murata Manufacturing Co."}
{0x044faa, "Ruckus Wireless"}
{0x045453, "Apple"}
{0x0455ca, "BriView (Xiamen)"}
{0x045a95, "Nokia"}
{0x045c06, "Zmodo Technology"}
{0x045d56, "camtron industrial"}
{0x0462d7, "Alstom Hydro France"}
{0x0463e0, "Nome Oy"}
{0x046d42, "Bryston"}
{0x0470bc, "Globalstar"}
{0x0474a1, "Aligera Equipamentos Digitais Ltda"}
{0x0475f5, "Csst"}
{0x04766e, "Alps Co"}
{0x047d7b, "Quanta Computer"}
{0x0481ae, "Clack"}
{0x04888c, "Eifelwerk Butler Systeme GmbH"}
{0x048a15, "Avaya"}
{0x0494a1, "Catch THE Wind"}
{0x049f81, "Simena"}
{0x04a3f3, "Emicon"}
{0x04a82a, "Nokia"}
{0x04b3b6, "Seamap (UK)"}
{0x04b466, "BSP Co."}
{0x04c05b, "Tigo Energy"}
{0x04c06f, "Huawei Device Co."}
{0x04c1b9, "Fiberhome Telecommunication Tech.Co."}
{0x04c5a4, "Cisco Systems"}
{0x04c880, "Samtec"}
{0x04d783, "Y&H E&C Co."}
{0x04dd4c, "IPBlaze"}
{0x04e0c4, "Triumph-adler AG"}
{0x04e1c8, "IMS Solues em Energia Ltda."}
{0x04e2f8, "AEP srl"}
{0x04e451, "Texas Instruments"}
{0x04e548, "Cohda Wireless"}
{0x04e662, "Acroname"}
{0x04ee91, "x-fabric GmbH"}
{0x04f021, "Compex Systems Pte"}
{0x04f17d, "Tarana Wireless"}
{0x04f4bc, "Xena Networks"}
{0x04fe7f, "Cisco Systems"}
{0x04ff51, "Novamedia Innovision SP. Z O.O."}
{0x080001, "Computervision"}
{0x080002, "Bridge Communications"}
{0x080003, "Advanced Computer COMM."}
{0x080004, "Cromemco Incorporated"}
{0x080005, "Symbolics"}
{0x080006, "Siemens AG"}
{0x080007, "Apple Computer"}
{0x080008, "Bolt Beranek AND Newman"}
{0x080009, "Hewlett Packard"}
{0x08000a, "Nestar Systems Incorporated"}
{0x08000b, "Unisys"}
{0x08000c, "Miklyn Development CO."}
{0x08000d, "International Computers"}
{0x08000e, "NCR"}
{0x08000f, "Mitel"}
{0x080011, "Tektronix"}
{0x080012, "Bell Atlantic Integrated SYST."}
{0x080013, "Exxon"}
{0x080014, "Excelan"}
{0x080015, "STC Business Systems"}
{0x080016, "Barrister Info SYS"}
{0x080017, "National Semiconductor"}
{0x080018, "Pirelli Focom Networks"}
{0x080019, "General Electric"}
{0x08001a, "Tiara/ 10net"}
{0x08001b, "EMC"}
{0x08001c, "Kdd-kokusai Debnsin Denwa CO."}
{0x08001d, "Able Communications"}
{0x08001e, "Apollo Computer"}
{0x08001f, "Sharp"}
{0x080020, "Oracle"}
{0x080021, "3M Company"}
{0x080022, "NBI"}
{0x080023, "Panasonic Communications Co."}
{0x080024, "10net Communications/dca"}
{0x080025, "Control Data"}
{0x080026, "Norsk Data A.S."}
{0x080027, "Cadmus Computer Systems"}
{0x080028, "Texas Instruments"}
{0x080029, "Megatek"}
{0x08002a, "Mosaic Technologies"}
{0x08002b, "Digital Equipment"}
{0x08002c, "Britton LEE"}
{0x08002d, "Lan-tec"}
{0x08002e, "Metaphor Computer Systems"}
{0x08002f, "Prime Computer"}
{0x080030, "Network Research"}
{0x080030, "Cern"}
{0x080030, "Royal Melbourne Inst OF Tech"}
{0x080031, "Little Machines"}
{0x080032, "Tigan Incorporated"}
{0x080033, "Bausch & Lomb"}
{0x080034, "Filenet"}
{0x080035, "Microfive"}
{0x080036, "Intergraph"}
{0x080037, "Fuji-xerox CO."}
{0x080038, "Bulls."}
{0x080039, "Spider Systems Limited"}
{0x08003a, "Orcatech"}
{0x08003b, "Torus Systems Limited"}
{0x08003c, "Schlumberger Well Services"}
{0x08003d, "Cadnetix Corporations"}
{0x08003e, "Codex"}
{0x08003f, "Fred Koschara Enterprises"}
{0x080040, "Ferranti Computer SYS. Limited"}
{0x080041, "Racal-milgo Information SYS.."}
{0x080042, "Japan Macnics"}
{0x080043, "Pixel Computer"}
{0x080044, "David Systems"}
{0x080045, "Concurrent Computer"}
{0x080046, "Sony"}
{0x080047, "Sequent Computer Systems"}
{0x080048, "Eurotherm Gauging Systems"}
{0x080049, "Univation"}
{0x08004a, "Banyan Systems"}
{0x08004b, "Planning Research"}
{0x08004c, "Hydra Computer Systems"}
{0x08004d, "Corvus Systems"}
{0x08004e, "3com Europe"}
{0x08004f, "Cygnet Systems"}
{0x080050, "Daisy Systems"}
{0x080051, "Experdata"}
{0x080052, "Insystec"}
{0x080053, "Middle East TECH. University"}
{0x080055, "Stanford Telecomm."}
{0x080056, "Stanford Linear Accel. Center"}
{0x080057, "Evans & Sutherland"}
{0x080058, "Systems Concepts"}
{0x080059, "A/S Mycron"}
{0x08005a, "IBM"}
{0x08005b, "VTA Technologies"}
{0x08005c, "Four Phase Systems"}
{0x08005d, "Gould"}
{0x08005e, "Counterpoint Computer"}
{0x08005f, "Saber Technology"}
{0x080060, "Industrial Networking"}
{0x080061, "Jarogate"}
{0x080062, "General Dynamics"}
{0x080063, "Plessey"}
{0x080064, "Autophon AG"}
{0x080065, "Genrad"}
{0x080066, "Agfa"}
{0x080067, "Comdesign"}
{0x080068, "Ridge Computers"}
{0x080069, "Silicon Graphics"}
{0x08006a, "ATT Bell Laboratories"}
{0x08006b, "Accel Technologies"}
{0x08006c, "Suntek Technology Int'l"}
{0x08006d, "Whitechapel Computer Works"}
{0x08006e, "Masscomp"}
{0x08006f, "Philips Apeldoorn B.V."}
{0x080070, "Mitsubishi Electric"}
{0x080071, "Matra (dsie)"}
{0x080072, "Xerox Univ Grant Program"}
{0x080073, "Tecmar"}
{0x080074, "Casio Computer CO."}
{0x080075, "Dansk Data Electronik"}
{0x080076, "PC LAN Technologies"}
{0x080077, "TSL Communications"}
{0x080078, "Accell"}
{0x080079, "THE Droid Works"}
{0x08007a, "Indata"}
{0x08007b, "Sanyo Electric CO."}
{0x08007c, "Vitalink Communications"}
{0x08007e, "Amalgamated Wireless(aus)"}
{0x08007f, "Carnegie-mellon University"}
{0x080080, "AES Data"}
{0x080081, ",astech"}
{0x080082, "Veritas Software"}
{0x080083, "Seiko Instruments"}
{0x080084, "Tomen Electronics"}
{0x080085, "Elxsi"}
{0x080086, "Konica Minolta Holdings"}
{0x080087, "Xyplex"}
{0x080088, "Brocade Communications Systems"}
{0x080089, "Kinetics"}
{0x08008a, "Performance Technology"}
{0x08008b, "Pyramid Technology"}
{0x08008c, "Network Research"}
{0x08008d, "Xyvision"}
{0x08008e, "Tandem Computers"}
{0x08008f, "Chipcom"}
{0x080090, "Sonoma Systems"}
{0x080d84, "GECO"}
{0x081196, "Intel Corporate"}
{0x081443, "Unibrain S.A."}
{0x081651, "Shenzhen Sea Star Technology Co."}
{0x081735, "Cisco Systems"}
{0x0817f4, "IBM"}
{0x08181a, "zte"}
{0x08184c, "A. S. Thomas"}
{0x0819a6, "Huawei Technologies Co."}
{0x081ff3, "Cisco Systems"}
{0x082522, "Advansee"}
{0x082ad0, "SRD Innovations"}
{0x082e5f, "Hewlett Packard"}
{0x08379c, "Topaz Co."}
{0x0838a5, "Funkwerk plettac electronic GmbH"}
{0x084e1c, "H2A Systems"}
{0x084ebf, "Broad Net Mux"}
{0x08512e, "Orion Diagnostica Oy"}
{0x087572, "Obelux Oy"}
{0x087618, "ViE Technologies Sdn. Bhd."}
{0x087695, "Auto Industrial Co."}
{0x0876ff, "Thomson Telecom Belgium"}
{0x08863b, "Belkin International"}
{0x088dc8, "Ryowa Electronics Co."}
{0x088f2c, "Hills Sound Vision & Lighting"}
{0x089f97, "Leroy Automation"}
{0x08a12b, "ShenZhen EZL Technology Co."}
{0x08a95a, "Azurewave"}
{0x08aca5, "Benu Video"}
{0x08b4cf, "Abicom International"}
{0x08b7ec, "Wireless Seismic"}
{0x08bbcc, "Ak-nord EDV Vertriebsges. mbH"}
{0x08be09, "Astrol Electronic AG"}
{0x08d09f, "Cisco Systems"}
{0x08d29a, "Proformatique"}
{0x08d5c0, "Seers Technology Co."}
{0x08e672, "Jebsee Electronics Co."}
{0x08ea44, "Aerohive Networks"}
{0x08f2f4, "Net One Partners Co."}
{0x08f6f8, "GET Engineering"}
{0x08fae0, "Fohhn Audio AG"}
{0x08fc52, "OpenXS BV"}
{0x0c130b, "Uniqoteq"}
{0x0c15c5, "Sdtec Co."}
{0x0c17f1, "Telecsys"}
{0x0c1dc2, "SeAH Networks"}
{0x0c2755, "Valuable Techologies Limited"}
{0x0c37dc, "Huawei Technologies Co."}
{0x0c3956, "Observator instruments"}
{0x0c3c65, "Dome Imaging"}
{0x0c469d, "MS Sedco"}
{0x0c4c39, "Mitrastar Technology "}
{0x0c51f7, "Chauvin Arnoux"}
{0x0c5a19, "Axtion Sdn Bhd"}
{0x0c6076, "Hon Hai Precision Ind. Co."}
{0x0c6e4f, "PrimeVOLT Co."}
{0x0c74c2, "Apple"}
{0x0c7523, "Beijing Gehua Catv Network Co."}
{0x0c771a, "Apple"}
{0x0c7d7c, "Kexiang Information Technology Co"}
{0x0c8112, "Private"}
{0x0c8230, "Shenzhen Magnus Technologies Co."}
{0x0c826a, "Wuhan Huagong Genuine Optics Technology Co."}
{0x0c8411, "A.O. Smith Water Products"}
{0x0c8525, "Cisco Systems"}
{0x0c8bfd, "Intel Corporate"}
{0x0c8d98, "TOP Eight IND"}
{0x0c924e, "Rice Lake Weighing Systems"}
{0x0c9d56, "Consort Controls"}
{0x0c9e91, "Sankosha"}
{0x0ca138, "Blinq Wireless"}
{0x0ca2f4, "Chameleon Technology (UK) Limited"}
{0x0ca402, "Alcatel Lucent IPD"}
{0x0ca42a, "OB Telecom Electronic Technology Co."}
{0x0caf5a, "Genus Power Infrastructures Limited"}
{0x0cbf15, "Genetec"}
{0x0cc0c0, "Magneti Marelli Sistemas Electronicos Mexico"}
{0x0cc3a7, "Meritec"}
{0x0cc6ac, "Dags"}
{0x0cc9c6, "Samwin Hong Kong Limited"}
{0x0ccdd3, "Eastriver Technology CO."}
{0x0cd292, "Intel Corporate"}
{0x0cd2b5, "Binatone Telecommunication Pvt."}
{0x0cd502, "Westell"}
{0x0cd696, "Amimon"}
{0x0cd7c2, "Axium Technologies"}
{0x0cddef, "Nokia"}
{0x0cdfa4, "Samsung Electronics Co."}
{0x0ce5d3, "DH electronics GmbH"}
{0x0ce709, "Fox Crypto B.V."}
{0x0ce82f, "Bonfiglioli Vectron GmbH"}
{0x0ce936, "Elimos srl"}
{0x0ceee6, "Hon Hai Precision Ind. Co."}
{0x0cef7c, "AnaCom"}
{0x0cf0b4, "Globalsat International Technology"}
{0x0cf3ee, "EM Microelectronic"}
{0x0cfc83, "Airoha Technology,"}
{0x100000, "Private"}
{0x10005a, "IBM"}
{0x1000e8, "National Semiconductor"}
{0x1000fd, "LaonPeople"}
{0x10090c, "Janome Sewing Machine Co."}
{0x100ba9, "Intel Corporate"}
{0x100c24, "pomdevices"}
{0x100d2f, "Online Security"}
{0x100d32, "Embedian"}
{0x100e2b, "NEC Casio Mobile Communications"}
{0x1010b6, "McCain"}
{0x101212, "Vivo International"}
{0x1013ee, "Justec International Technology"}
{0x10189e, "Elmo Motion Control"}
{0x101b54, "Huawei Technologies Co."}
{0x101dc0, "Samsung Electronics Co."}
{0x101f74, "Hewlett-Packard Company "}
{0x102d96, "Looxcie"}
{0x102eaf, "Texas Instruments"}
{0x103711, "Simlink AS"}
{0x1040f3, "Apple"}
{0x104369, "Soundmax Electronic Limited "}
{0x10445a, "Shaanxi Hitech Electronic Co."}
{0x1045be, "Norphonic AS"}
{0x1045f8, "LNT-Automation GmbH"}
{0x1056ca, "Peplink International"}
{0x1062c9, "Adatis GmbH & Co. KG"}
{0x1064e2, "ADFweb.com s.r.l."}
{0x1065a3, "Panamax"}
{0x106f3f, "Buffalo"}
{0x1071f9, "Cloud Telecomputers"}
{0x10768a, "EoCell"}
{0x1078d2, "Elitegroup Computer System CO."}
{0x1083d2, "Microseven Systems"}
{0x10880f, "Daruma Telecomunicaes E Informtica S/A"}
{0x108ccf, "Cisco Systems"}
{0x1093e9, "Apple"}
{0x109add, "Apple"}
{0x10a13b, "Fujikura Rubber"}
{0x10a932, "Beijing Cyber Cloud Technology Co. "}
{0x10b7f6, "Plastoform Industries"}
{0x10baa5, "Gana I&C CO."}
{0x10bf48, "Asustek Computer"}
{0x10c2ba, "UTT Co."}
{0x10c586, "BIO Sound LAB CO."}
{0x10c61f, "Huawei Technologies Co."}
{0x10c6fc, "Garmin International"}
{0x10c73f, "Midas Klark Teknik"}
{0x10ca81, "Precia"}
{0x10ccdb, "Aximum Produits Electroniques"}
{0x10e2d5, "Qi Hardware"}
{0x10e3c7, "Seohwa Telecom"}
{0x10e4af, "APR"}
{0x10e6ae, "Source Technologies"}
{0x10e8ee, "PhaseSpace"}
{0x10eed9, "Canoga Perkins"}
{0x10f96f, "LG Electronics"}
{0x10f9ee, "Nokia"}
{0x10fc54, "Shany Electronic Co."}
{0x1100aa, "Private"}
{0x140708, "Private"}
{0x1407e0, "Abrantix AG"}
{0x14144b, "Fujian Star-net Communication Co."}
{0x141a51, "Treetech Sistemas Digitais"}
{0x141bbd, "Volex"}
{0x142df5, "Amphitech"}
{0x14307a, "Avermetrics"}
{0x1435b3, "Future Designs"}
{0x143605, "Nokia"}
{0x14373b, "Procom Systems"}
{0x143aea, "Dynapower Company"}
{0x143e60, "Alcatel-Lucent"}
{0x144978, "Digital Control Incorporated"}
{0x144c1a, "Max Communication GmbH"}
{0x145412, "Entis Co."}
{0x145a05, "Apple"}
{0x146308, "Jabil Circuit (shanghai)"}
{0x146e0a, "Private"}
{0x147373, "Tubitak Uekae"}
{0x147411, "RIM"}
{0x147db3, "JOA Telecom.co."}
{0x147dc5, "Murata Manufacturing Co."}
{0x14825b, "Hefei Radio Communication Technology Co."}
{0x148a70, "ADS GmbH"}
{0x148fc6, "Apple"}
{0x149090, "KongTop industrial(shen zhen)CO."}
{0x14a62c, "S.M. Dezac S.A."}
{0x14a86b, "ShenZhen Telacom Science&Technology Co."}
{0x14a9e3, "MST"}
{0x14b1c8, "InfiniWing"}
{0x14b73d, "Archean Technologies"}
{0x14c21d, "Sabtech Industries"}
{0x14cf8d, "Ohsung Electronics CO."}
{0x14d4fe, "Pace plc"}
{0x14d64d, "D-Link International"}
{0x14d76e, "Conch Electronic Co."}
{0x14dae9, "Asustek Computer"}
{0x14e4ec, "mLogic"}
{0x14e6e4, "Tp-link Technologies CO."}
{0x14eb33, "BSMediasoft Co."}
{0x14ee9d, "AirNav Systems"}
{0x14f0c5, "Xtremio"}
{0x14feaf, "Sagittar Limited"}
{0x14feb5, "Dell"}
{0x1801e3, "Elektrobit Wireless Communications"}
{0x180373, "Dell"}
{0x1803fa, "IBT Interfaces"}
{0x180675, "Dilax Intelcom Gmbh"}
{0x180b52, "Nanotron Technologies GmbH"}
{0x180c77, "Westinghouse Electric Company"}
{0x181420, "TEB SAS"}
{0x181456, "Nokia"}
{0x181714, "Daewoois"}
{0x18193f, "Tamtron Oy"}
{0x182032, "Apple"}
{0x182861, "AirTies Wireless Networks"}
{0x182b05, "8D Technologies"}
{0x182c91, "Concept Development"}
{0x183451, "Apple"}
{0x183825, "Wuhan Lingjiu High-tech Co."}
{0x183bd2, "BYD Precision Manufacture Company"}
{0x183da2, "Intel Corporate"}
{0x18422f, "Alcatel Lucent"}
{0x184617, "Samsung Electronics"}
{0x184e94, "Messoa Technologies"}
{0x185933, "Cisco Spvtg"}
{0x1866e3, "Veros Systems"}
{0x186751, "Komeg Industrielle Messtechnik Gmbh"}
{0x186d99, "Adanis"}
{0x187c81, "Valeo Vision Systems"}
{0x1880ce, "Barberry Solutions"}
{0x1880f5, "Alcatel-Lucent Shanghai Bell Co."}
{0x1886ac, "Nokia Danmark A/S"}
{0x188796, "HTC"}
{0x188ed5, "Philips Innovative Application NV "}
{0x18922c, "Virtual Instruments"}
{0x1897ff, "TechFaith Wireless Technology Limited"}
{0x18a905, "Hewlett-Packard Company"}
{0x18abf5, "Ultra Electronics - Electrics"}
{0x18ad4d, "Polostar Technology"}
{0x18aebb, "Siemens Programm- und Systementwicklung GmbH&Co.KG"}
{0x18af9f, "Digitronic Automationsanlagen Gmbh"}
{0x18b209, "Torrey Pines Logic"}
{0x18b3ba, "Netlogic AB"}
{0x18b430, "Nest Labs"}
{0x18b591, "I-Storm"}
{0x18b79e, "Invoxia"}
{0x18c086, "Broadcom"}
{0x18c451, "Tucson Embedded Systems"}
{0x18d071, "Dasan SMC"}
{0x18d66a, "Inmarsat"}
{0x18e288, "STT Condigi"}
{0x18e7f4, "Apple"}
{0x18e80f, "Viking Electronics"}
{0x18ef63, "Cisco Systems"}
{0x18f46a, "Hon Hai Precision Ind. Co."}
{0x18f650, "Multimedia Pacific Limited"}
{0x18fc9f, "Changhe Electronics Co."}
{0x1c0656, "IDY"}
{0x1c0b52, "Epicom S.A"}
{0x1c0fcf, "Sypro Optics GmbH"}
{0x1c129d, "Ieee PES Psrc/sub"}
{0x1c1448, "Motorola Mobility"}
{0x1c17d3, "Cisco Systems"}
{0x1c184a, "ShenZhen RicherLink Technologies Co."}
{0x1c19de, "eyevis GmbH"}
{0x1c1d67, "Huawei Device Co."}
{0x1c334d, "ITS Telecom"}
{0x1c35f1, "NEW Lift Neue Elektronische Wege Steuerungsbau GmbH"}
{0x1c3a4f, "AccuSpec Electronics"}
{0x1c3de7, "Sigma Koki Co."}
{0x1c4593, "Texas Instruments"}
{0x1c4bd6, "AzureWave"}
{0x1c51b5, "Techaya"}
{0x1c5c55, "Prima Cinema"}
{0x1c62b8, "Samsung Electronics Co."}
{0x1c659d, "Liteon Technology"}
{0x1c69a5, "Research In Motion"}
{0x1c6bca, "Mitsunami Co."}
{0x1c6f65, "Giga-byte Technology Co."}
{0x1c7508, "Compal Information (kunshan) CO."}
{0x1c7c11, "EID"}
{0x1c7c45, "Vitek Industrial Video Products"}
{0x1c7ee5, "D-Link International"}
{0x1c83b0, "Linked IP GmbH"}
{0x1c8e8e, "DB Communication & Systems Co."}
{0x1c8f8a, "Phase Motion Control SpA"}
{0x1c955d, "I-lax Electronics"}
{0x1c973d, "Pricom Design"}
{0x1caa07, "Cisco Systems"}
{0x1caba7, "Apple"}
{0x1caff7, "D-link International PTE Limited"}
{0x1cb094, "HTC"}
{0x1cb17f, "NEC AccessTechnica"}
{0x1cb243, "TDC A/S"}
{0x1cbba8, "Ojsc "ufimskiy Zavod "promsvyaz""}
{0x1cbd0e, "Amplified Engineering"}
{0x1cbdb9, "D-link International PTE Limited"}
{0x1cc1de, "Hewlett-Packard Company"}
{0x1cc63c, "Arcadyan Technology"}
{0x1cd40c, "Kriwan Industrie-Elektronik GmbH"}
{0x1cdf0f, "Cisco Systems"}
{0x1ce165, "Marshal"}
{0x1ce192, "Qisda"}
{0x1ce2cc, "Texas Instruments"}
{0x1cf061, "Scaps Gmbh"}
{0x1cf5e7, "Turtle Industry Co."}
{0x1cfea7, "IDentytech Solutins"}
{0x200505, "Radmax Communication Private Limited"}
{0x2005e8, "OOO "InProMedia""}
{0x200a5e, "Xiangshan Giant Eagle Technology Developing co."}
{0x20107a, "Gemtek Technology Co."}
{0x201257, "Most Lucky Trading"}
{0x2013e0, "Samsung Electronics Co."}
{0x2021a5, "LG Electronics"}
{0x202598, "Teleview"}
{0x202bc1, "Huawei Device Co."}
{0x202cb7, "Kong Yue Electronics & Information Industry (Xinhui)"}
{0x203706, "Cisco Systems"}
{0x2037bc, "Kuipers Electronic Engineering BV"}
{0x204005, "feno GmbH"}
{0x20415a, "Smarteh d.o.o."}
{0x2046a1, "Vecow Co."}
{0x2046f9, "Advanced Network Devices (dba:AND)"}
{0x204aaa, "Hanscan Spain S.A."}
{0x204e6b, "Axxana(israel)"}
{0x204e7f, "Netgear"}
{0x2059a0, "Paragon Technologies"}
{0x205b2a, "Private"}
{0x205b5e, "Shenzhen Wonhe Technology Co."}
{0x206a8a, "Wistron InfoComm Manufacturing(Kunshan)Co."}
{0x206aff, "Atlas Elektronik UK Limited"}
{0x206fec, "Braemac CA"}
{0x207600, "Actiontec Electronics"}
{0x207c8f, "Quanta Microsystems"}
{0x20a2e7, "Lee-Dickens"}
{0x20aa25, "Ip-net"}
{0x20aa4b, "Cisco-Linksys"}
{0x20b0f7, "Enclustra GmbH"}
{0x20b399, "Enterasys"}
{0x20b7c0, "Omicron electronics GmbH"}
{0x20bbc6, "Jabil Circuit Hungary"}
{0x20bfdb, "DVL"}
{0x20c8b3, "Shenzhen Bul-tech Co."}
{0x20cf30, "Asustek Computer"}
{0x20d5ab, "Korea Infocom Co."}
{0x20d607, "Nokia"}
{0x20d906, "Iota"}
{0x20e564, "Motorola Mobility"}
{0x20eec6, "Elefirst Science & Tech Co"}
{0x20f3a3, "Huawei Technologies Co."}
{0x20fabb, "Cambridge Executive Limited"}
{0x20fdf1, "3com Europe"}
{0x20fecd, "System In Frontier"}
{0x20fedb, "M2M SolutionS."}
{0x240b2a, "Viettel Group"}
{0x240bb1, "Kostal Industrie Elektrik Gmbh"}
{0x241a8c, "Squarehead Technology AS"}
{0x241f2c, "Calsys"}
{0x2421ab, "Sony Ericsson Mobile Communications"}
{0x24374c, "Cisco Spvtg"}
{0x2437ef, "EMC Electronic Media Communication SA"}
{0x243c20, "Dynamode Group"}
{0x244597, "Gemue Gebr. Mueller Apparatebau"}
{0x24470e, "PentronicAB"}
{0x24497b, "Innovative Converged Devices"}
{0x245fdf, "Kyocera"}
{0x246511, "AVM GmbH"}
{0x247703, "Intel Corporate"}
{0x24828a, "Prowave Technologies"}
{0x2486f4, "Ctek"}
{0x248707, "SEnergy"}
{0x249442, "Open Road Solutions "}
{0x24a42c, "Koukaam a.s."}
{0x24a937, "Pure Storage"}
{0x24ab81, "Apple"}
{0x24af4a, "Alcatel-Lucent-IPD"}
{0x24af54, "Nexgen Mediatech"}
{0x24b657, "Cisco Systems"}
{0x24b6b8, "Friem SPA"}
{0x24b6fd, "Dell"}
{0x24b88c, "Crenus Co."}
{0x24b8d2, "Opzoon Technology Co."}
{0x24ba30, "Technical Consumer Products"}
{0x24bbc1, "Absolute Analysis"}
{0x24bc82, "Dali Wireless"}
{0x24bf74, "Private"}
{0x24c0b3, "RSF"}
{0x24c86e, "Chaney Instrument Co."}
{0x24c9de, "Genoray"}
{0x24cbe7, "MYK"}
{0x24cf21, "Shenzhen State Micro Technology Co."}
{0x24d2cc, "SmartDrive Systems"}
{0x24dab6, "Sistemas de Gestin Energtica S.A. de C.V."}
{0x24dbac, "Huawei Device Co."}
{0x24dbad, "ShopperTrak RCT"}
{0x24e6ba, "JSC Zavod im. Kozitsky"}
{0x24ec99, "Askey Computer"}
{0x24f0ff, "GHT Co."}
{0x2804e0, "Fermax Electronicau."}
{0x28061e, "Ningbo Global Useful Electric Co."}
{0x28068d, "ITL"}
{0x280cb8, "Mikrosay Yazilim ve Elektronik A.S."}
{0x280dfc, "Sony Computer Entertainment"}
{0x28107b, "D-Link International"}
{0x281471, "Lantis co."}
{0x28162e, "2Wire"}
{0x2817ce, "Omnisense"}
{0x2818fd, "Aditya Infotech"}
{0x2826a6, "PBR electronics GmbH"}
{0x283410, "Enigma Diagnostics Limited"}
{0x283737, "Apple"}
{0x2838cf, "Gen2wave"}
{0x2839e7, "Preceno Technology Pte.Ltd."}
{0x283ce4, "Huawei Technologies Co."}
{0x28401a, "C8 MediSensors"}
{0x284121, "OptiSense Network"}
{0x284846, "GridCentric"}
{0x284c53, "Intune Networks"}
{0x285132, "Shenzhen Prayfly Technology Co."}
{0x285fdb, "Huawei Device Co."}
{0x286046, "Lantech Communications Global"}
{0x286094, "Capelec"}
{0x286ab8, "Apple"}
{0x286aba, "Ieee-sa"}
{0x286ed4, "Huawei Technologies Co."}
{0x287184, "Spire Payments"}
{0x2872c5, "Smartmatic"}
{0x2872f0, "Athena"}
{0x28852d, "Touch Networks"}
{0x288915, "CashGuard Sverige AB"}
{0x2893fe, "Cisco Systems"}
{0x28940f, "Cisco Systems"}
{0x28a574, "Miller Electric Mfg. Co."}
{0x28af0a, "Sirius XM Radio"}
{0x28b0cc, "Xenya d.o.o."}
{0x28ba18, "NextNav"}
{0x28be9b, "Technicolor USA"}
{0x28c0da, "Juniper Networks"}
{0x28c718, "Altierre"}
{0x28ccff, "Corporacion Empresarial Altra SL"}
{0x28cd1c, "Espotel Oy"}
{0x28cd4c, "Individual Computers GmbH"}
{0x28cfda, "Apple"}
{0x28d1af, "Nokia"}
{0x28d576, "Premier Wireless"}
{0x28d997, "Yuduan Mobile Co."}
{0x28e02c, "Apple"}
{0x28e297, "Shanghai InfoTM Microelectronics Co."}
{0x28e608, "Tokheim"}
{0x28e794, "Microtime Computer"}
{0x28e7cf, "Apple"}
{0x28ed58, "JAG Jakob AG"}
{0x28ee2c, "Frontline Test Equipment"}
{0x28ef01, "Private"}
{0x28f358, "2C - Trifonov & Co"}
{0x28f606, "Syes srl"}
{0x28fbd3, "Shanghai RagenTek Communication Technology Co."}
{0x2c002c, "Unowhy"}
{0x2c0033, "EControls"}
{0x2c00f7, "XOS"}
{0x2c0623, "Win Leader"}
{0x2c10c1, "Nintendo Co."}
{0x2c1984, "IDN Telecom"}
{0x2c1eea, "Aerodev"}
{0x2c2172, "Juniper Networks"}
{0x2c27d7, "Hewlett-Packard Company"}
{0x2c2d48, "bct electronic GesmbH"}
{0x2c3068, "Pantech Co."}
{0x2c3427, "Erco &amp; Gener"}
{0x2c36a0, "Capisco Limited"}
{0x2c36f8, "Cisco Systems"}
{0x2c3a28, "Fagor Electrnica"}
{0x2c3f38, "Cisco Systems"}
{0x2c3f3e, "Alge-Timing GmbH"}
{0x2c4138, "Hewlett-Packard Company "}
{0x2c4401, "Samsung Electronics Co."}
{0x2c542d, "Cisco Systems"}
{0x2c67fb, "ShenZhen Zhengjili Electronics Co."}
{0x2c6bf5, "Juniper networks"}
{0x2c750f, "Shanghai Dongzhou-Lawton Communication Technology Co."}
{0x2c768a, "Hewlett-Packard Company"}
{0x2c7afe, "IEE&E "Black" ops"}
{0x2c7ecf, "Onzo"}
{0x2c8065, "Harting of North America"}
{0x2c8158, "Hon Hai Precision Ind. Co."}
{0x2c8bf2, "Hitachi Metals America"}
{0x2c9127, "Eintechno"}
{0x2c9717, "I.c.y. B.V."}
{0x2c9e5f, "Motorola Mobility"}
{0x2c9efc, "Canon"}
{0x2ca157, "Acromate"}
{0x2ca780, "True Technologies"}
{0x2ca835, "RIM"}
{0x2cb05d, "Netgear"}
{0x2cb0df, "Soliton Technologies Pvt"}
{0x2cb69d, "RED Digital Cinema"}
{0x2cbe97, "Ingenieurbuero Bickele und Buehler GmbH"}
{0x2cc260, "Ravello Systems"}
{0x2ccd27, "Precor"}
{0x2ccd43, "Summit Technology Group"}
{0x2cd1da, "Sanjole"}
{0x2cd2e7, "Nokia"}
{0x2cdd0c, "Discovergy GmbH"}
{0x2ce412, "Sagemcom SAS"}
{0x2cee26, "Petroleum Geo-Services"}
{0x2cf4c5, "Avaya"}
{0x300b9c, "Delta Mobile Systems"}
{0x30142d, "Piciorgros GmbH"}
{0x30144a, "Wistron Neweb"}
{0x30168d, "ProLon"}
{0x3017c8, "Sony Ericsson Mobile Communications AB"}
{0x3018cf, "Deos Control Systems Gmbh"}
{0x301a28, "Mako Networks"}
{0x302de8, "JDA, (JDA Systems)"}
{0x3032d4, "Hanilstm Co."}
{0x3037a6, "Cisco Systems"}
{0x303855, "Nokia"}
{0x303926, "Sony Ericsson Mobile Communications AB"}
{0x303955, "Shenzhen Jinhengjia Electronic Co."}
{0x3039f2, "ADB Broadband Italia"}
{0x304174, "Altec Lansing"}
{0x30469a, "Netgear"}
{0x30493b, "Nanjing Z-Com Wireless Co."}
{0x304c7e, "Panasonic Electric Works Automation Controls Techno Co."}
{0x304ec3, "Tianjin Techua Technology Co."}
{0x30525a, "NST Co."}
{0x3055ed, "Trex Network"}
{0x3057ac, "Irlab"}
{0x306118, "Paradom"}
{0x30688c, "Reach Technology"}
{0x30694b, "RIM"}
{0x306cbe, "Skymotion Technology (HK) Limited"}
{0x306e5c, "Validus Technologies"}
{0x3071b2, "Hangzhou Prevail Optoelectronic Equipment Co."}
{0x307c30, "RIM"}
{0x307ecb, "SFR"}
{0x308730, "Huawei Device Co."}
{0x308cfb, "Dropcam"}
{0x30b216, "Hytec Geraetebau GmbH"}
{0x30b3a2, "Shenzhen Heguang Measurement & Control Technology Co."}
{0x30de86, "Cedac Software S.r.l."}
{0x30e48e, "Vodafone UK"}
{0x30e4db, "Cisco Systems"}
{0x30eb25, "Intek Digital"}
{0x30efd1, "Alstom Strongwish (Shenzhen) Co."}
{0x30f9ed, "Sony"}
{0x340804, "D-Link"}
{0x34159e, "Apple"}
{0x342109, "Jensen Scandinavia AS"}
{0x34255d, "Shenzhen Loadcom Technology Co."}
{0x3429ea, "MCD Electronics SP. Z O.O."}
{0x342f6e, "Anywire"}
{0x3440b5, "IBM"}
{0x344b3d, "Fiberhome Telecommunication Tech.Co."}
{0x344b50, "ZTE"}
{0x344f69, "Ekinops SAS"}
{0x3451c9, "Apple"}
{0x345b11, "EVI Heat AB"}
{0x34684a, "Teraworks Co."}
{0x346f92, "White Rodgers Division"}
{0x347877, "O-NET Communications(Shenzhen) Limited"}
{0x347e39, "Nokia Danmark A/S"}
{0x3482de, "Kayo Technology"}
{0x348302, "iForcom Co."}
{0x34862a, "Heinz Lackmann GmbH & Co KG"}
{0x3497fb, "Advanced RF Technologies"}
{0x3499d7, "Universal Flow Monitors"}
{0x349a0d, "ZBD Displays"}
{0x34a183, "AWare"}
{0x34a55d, "Technosoft International SRL"}
{0x34a709, "Trevil srl"}
{0x34a7ba, "Fischer International Systems"}
{0x34aa99, "Alcatel-Lucent"}
{0x34aaee, "Mikrovisatos Servisas UAB"}
{0x34b571, "Plds"}
{0x34ba51, "Se-Kure Controls"}
{0x34ba9a, "Asiatelco Technologies Co."}
{0x34bca6, "Beijing Ding Qing Technology"}
{0x34bdf9, "Shanghai WDK Industrial Co."}
{0x34c3ac, "Samsung Electronics"}
{0x34c69a, "Enecsys"}
{0x34c731, "Alps Electric Co"}
{0x34ce94, "Parsec (Pty)"}
{0x34d09b, "MobilMAX Technology"}
{0x34d2c4, "Rena Gmbh Print Systeme"}
{0x34df2a, "Fujikon Industrial Co.,Limited"}
{0x34e0d7, "Dongguan Qisheng Electronics Industrial CO."}
{0x34ef44, "2Wire"}
{0x34ef8b, "NTT Communications"}
{0x34f39b, "WizLAN"}
{0x34f968, "Atek Products"}
{0x34fc6f, "Alcea"}
{0x380197, "Toshiba Samsung Storage Technolgoy Korea"}
{0x380a0a, "Sky-City Communication and Electronics Limited Company"}
{0x380a94, "Samsung Electronics Co."}
{0x380dd4, "Primax Electronics"}
{0x3816d1, "Samsung Electronics Co."}
{0x38229d, "ADB Broadband Italia"}
{0x3822d6, "H3C Technologies Co., Limited"}
{0x3826cd, "Andtek"}
{0x3828ea, "Fujian Netcom Technology Co."}
{0x3831ac, "WEG"}
{0x383f10, "DBL Technology"}
{0x38458c, "MyCloud Technology"}
{0x384608, "ZTE"}
{0x38521a, "Alcatel-Lucent 7705"}
{0x38580c, "Panaccess Systems GmbH"}
{0x3859f9, "Hon Hai Precision Ind. Co."}
{0x385fc3, "Yu Jeong System,Ltd"}
{0x386077, "Pegatron"}
{0x3863f6, "3nod Multimedia(shenzhen)co."}
{0x386e21, "Wasion Group"}
{0x3872c0, "Comtrend"}
{0x388345, "Tp-link Technologies CO."}
{0x3891fb, "Xenox Holding BV"}
{0x389592, "Beijing Tendyron"}
{0x389f83, "OTN Systems N.V."}
{0x38a851, "Quickset International"}
{0x38a95f, "Actifio"}
{0x38bb23, "OzVision America"}
{0x38bf33, "NEC Casio Mobile Communications"}
{0x38c7ba, "CS Services Co."}
{0x38c85c, "Cisco Spvtg"}
{0x38d135, "EasyIO Sdn. Bhd."}
{0x38de60, "Mohlenhoff GmbH"}
{0x38e08e, "Mitsubishi Electric Co."}
{0x38e7d8, "HTC"}
{0x38e8df, "b gmbh medien + datenbanken"}
{0x38e98c, "Reco S.p.A."}
{0x38ece4, "Samsung Electronics"}
{0x38f8b7, "V2com Participacoes S.A."}
{0x38fec5, "Ellips B.V."}
{0x3c02b1, "Creation Technologies LP"}
{0x3c04bf, "Pravis Systemsltd.,"}
{0x3c05ab, "Product Creation Studio"}
{0x3c0754, "Apple"}
{0x3c096d, "Powerhouse Dynamics"}
{0x3c0fc1, "KBC Networks"}
{0x3c106f, "Albahith Technologies"}
{0x3c1915, "GFI Chrono Time"}
{0x3c197d, "Ericsson AB"}
{0x3c1a79, "Huayuan Technology CO."}
{0x3c1cbe, "Jadak"}
{0x3c26d5, "Sotera Wireless"}
{0x3c2763, "SLE quality engineering GmbH &amp; Co. KG"}
{0x3c2db7, "Texas Instruments"}
{0x3c2f3a, "Sforzato"}
{0x3c363d, "Nokia"}
{0x3c3888, "ConnectQuest"}
{0x3c39c3, "JW Electronics Co."}
{0x3c3a73, "Avaya"}
{0x3c438e, "Motorola Mobility"}
{0x3c4a92, "Hewlett-Packard Company"}
{0x3c4c69, "Infinity System S.L."}
{0x3c4e47, "Etronic A/S"}
{0x3c5a37, "Samsung Electronics"}
{0x3c5f01, "Synerchip Co."}
{0x3c6200, "Samsung electronics CO."}
{0x3c6278, "Shenzhen Jetnet Technology Co."}
{0x3c672c, "Sciovid"}
{0x3c6a7d, "Niigata Power Systems Co."}
{0x3c6f45, "Fiberpro"}
{0x3c7059, "MakerBot Industries"}
{0x3c7437, "RIM"}
{0x3c754a, "Motorola Mobility"}
{0x3c7db1, "Texas Instruments"}
{0x3c8bfe, "Samsung Electronics"}
{0x3c9157, "Hangzhou Yulong Conmunication Co."}
{0x3c98bf, "Quest Controls"}
{0x3c99f7, "Lansentechnology AB"}
{0x3c9f81, "Shenzhen Catic Bit Communications Technology Co."}
{0x3ca315, "Bless Information & Communications Co."}
{0x3ca72b, "MRV Communications (Networks)"}
{0x3ca9f4, "Intel Corporate"}
{0x3cb15b, "Avaya"}
{0x3cb17f, "Wattwatchers Ld"}
{0x3cb87a, "Private"}
{0x3cb9a6, "Belden Deutschland GmbH"}
{0x3cbdd8, "LG Electronics"}
{0x3cc0c6, "d&amp;b audiotechnik GmbH"}
{0x3cc1f6, "Melange Systems Pvt."}
{0x3cc99e, "Huiyang Technology Co."}
{0x3cce73, "Cisco Systems"}
{0x3cd0f8, "Apple"}
{0x3cd16e, "Telepower Communication Co."}
{0x3cd92b, "Hewlett-Packard Company"}
{0x3cdf1e, "Cisco Systems"}
{0x3ce5a6, "Hangzhou H3C Technologies Co."}
{0x3ce5b4, "Kidasen Industria E Comercio DE Antenas Ltda"}
{0x3ce624, "LG Display "}
{0x3cea4f, "2Wire"}
{0x3cf52c, "Dspecialists Gmbh"}
{0x3cf72a, "Nokia"}
{0x4001c6, "3com Europe"}
{0x40040c, "A&T"}
{0x400e67, "Tremol"}
{0x4012e4, "Compass-EOS"}
{0x4013d9, "Global ES"}
{0x401597, "Protect America"}
{0x40169f, "Tp-link Technologies CO."}
{0x4016fa, "EKM Metering"}
{0x4018b1, "Aerohive Networks"}
{0x4018d7, "Wyle Telemetry and Data Systems"}
{0x401d59, "Biometric Associates"}
{0x4022ed, "Digital Projection"}
{0x4025c2, "Intel Corporate"}
{0x402ba1, "Sony Ericsson Mobile Communications AB"}
{0x402cf4, "Universal Global Scientific Industrial Co."}
{0x403004, "Apple"}
{0x4037ad, "Macro Image Technology"}
{0x403cfc, "Apple"}
{0x404022, "ZIV"}
{0x40406b, "Icomera"}
{0x404a03, "ZyXEL Communications"}
{0x404d8e, "Huawei Device Co."}
{0x4050e0, "Milton Security Group"}
{0x40520d, "Pico Technology"}
{0x405539, "Cisco Systems"}
{0x405a9b, "Anovo"}
{0x405fbe, "RIM"}
{0x405fc2, "Texas Instruments"}
{0x40605a, "Hawkeye Tech Co."}
{0x406186, "Micro-star Int'l Co."}
{0x40618e, "Stella-Green Co"}
{0x40667a, "mediola - connected living AG"}
{0x406aab, "RIM"}
{0x406c8f, "Apple"}
{0x407b1b, "Mettle Networks"}
{0x4083de, "Motorola"}
{0x408493, "Clavister AB"}
{0x408a9a, "Titeng CO."}
{0x408b07, "Actiontec Electronics"}
{0x408bf6, "Shenzhen TCL New Technology Co;"}
{0x409558, "Aisino"}
{0x4097d1, "BK Electronics cc"}
{0x40984c, "Casacom Solutions AG"}
{0x40984e, "Texas Instruments"}
{0x40987b, "Aisino"}
{0x409fc7, "Baekchun ENC Co."}
{0x40a6a4, "PassivSystems"}
{0x40a6d9, "Apple"}
{0x40b2c8, "Nortel Networks"}
{0x40b3fc, "Logital Co. Limited "}
{0x40b7f3, "Motorola Mobility"}
{0x40ba61, "Arima Communications"}
{0x40bc8b, "itelio GmbH"}
{0x40bf17, "Digistar Telecom. SA"}
{0x40c245, "Shenzhen Hexicom Technology Co."}
{0x40c7c9, "Naviit"}
{0x40cd3a, "Z3 Technology"}
{0x40d32d, "Apple"}
{0x40d40e, "Biodata"}
{0x40d559, "Micro S.e.r.i."}
{0x40e793, "Shenzhen Siviton Technology Co."}
{0x40ecf8, "Siemens AG"}
{0x40ef4c, "Fihonest communication co."}
{0x40f14c, "ISE Europe Sprl"}
{0x40f407, "Nintendo Co."}
{0x40f4ec, "Cisco Systems"}
{0x40f52e, "Leica Microsystems (Schweiz) AG"}
{0x40fc89, "Motorola Mobility"}
{0x441319, "WKK Technology"}
{0x441ea1, "Hewlett-Packard Company"}
{0x4425bb, "Bamboo Entertainment"}
{0x442a60, "Apple"}
{0x442b03, "Cisco Systems"}
{0x44322a, "Avaya"}
{0x44348f, "MXT Industrial Ltda"}
{0x443719, "2 Save Energy"}
{0x44376f, "Young Electric Sign Co"}
{0x4437e6, "Hon Hai Precision Ind.Co.Ltd"}
{0x443d21, "Nuvolt"}
{0x443eb2, "Deotron Co."}
{0x444e1a, "Samsung Electronics Co."}
{0x444f5e, "Pan Studios Co."}
{0x4451db, "Raytheon BBN Technologies"}
{0x4454c0, "Thompson Aerospace"}
{0x44568d, "PNC Technologies  Co."}
{0x4456b7, "Spawn Labs"}
{0x445829, "Cisco Spvtg"}
{0x44599f, "Criticare Systems"}
{0x445ef3, "Tonalite Holding B.V."}
{0x445f7a, "Shihlin Electric & Engineering"}
{0x446132, "ecobee"}
{0x4468ab, "Juin Company, Limited"}
{0x446c24, "Reallin Electronic Co."}
{0x446d57, "Liteon Technology"}
{0x447c7f, "Innolight Technology"}
{0x447da5, "Vtion Information Technology (fujian) Co."}
{0x447e95, "Alpha and Omega"}
{0x448312, "Star-Net"}
{0x448500, "Intel"}
{0x4487fc, "Elitegroup Computer System CO."}
{0x448c52, "Ktis CO."}
{0x448e12, "DT Research"}
{0x448e81, "VIG"}
{0x4491db, "Shanghai Huaqin Telecom Technology Co."}
{0x449cb5, "Alcomp"}
{0x44a42d, "TCT Mobile Limited"}
{0x44a689, "Promax Electronica SA"}
{0x44a7cf, "Murata Manufacturing Co."}
{0x44a8c2, "Sewoo Tech CO."}
{0x44aa27, "udworks Co."}
{0x44aae8, "Nanotec Electronic GmbH & Co. KG"}
{0x44b382, "Kuang-chi Institute of Advanced Technology"}
{0x44c15c, "Texas Instruments"}
{0x44c233, "Guangzhou Comet Technology DevelopmentLtd"}
{0x44c9a2, "Greenwald Industries"}
{0x44d2ca, "Anvia TV Oy"}
{0x44d3ca, "Cisco Systems"}
{0x44d63d, "Talari Networks"}
{0x44d832, "Azurewave Technologies"}
{0x44d884, "Apple"}
{0x44dc91, "Planex Communications"}
{0x44dccb, "Semindia Systems PVT"}
{0x44e08e, "Cisco Spvtg"}
{0x44e49a, "Omnitronics"}
{0x44e4d9, "Cisco Systems"}
{0x44ed57, "Longicorn"}
{0x44f459, "Samsung Electronics"}
{0x48022a, "B-Link Electronic Limited"}
{0x481249, "Luxcom Technologies"}
{0x4813f3, "BBK Electronics"}
{0x48174c, "MicroPower technologies"}
{0x481bd2, "Intron Scientific co."}
{0x482cea, "Motorola Business Light Radios"}
{0x4833dd, "Zennio Avance Y Tecnologia"}
{0x48343d, "IEP GmbH"}
{0x484487, "Cisco Spvtg"}
{0x4844f7, "Samsung Electronics Co."}
{0x4846f1, "Uros Oy"}
{0x485b39, "Asustek Computer"}
{0x485d60, "Azurewave Technologies"}
{0x4860bc, "Apple"}
{0x4861a3, "Concern "Axion" JSC"}
{0x486b91, "Fleetwood Group"}
{0x486fd2, "StorSimple"}
{0x487119, "SGB Group"}
{0x488e42, "Digalog Gmbh"}
{0x4891f6, "Shenzhen Reach software technology CO."}
{0x489be2, "SCI Innovations"}
{0x48a22d, "Shenzhen Huaxuchang Telecom Technology Co."}
{0x48a6d2, "GJsun Optical Science and Tech Co."}
{0x48aa5d, "Store Electronic Systems"}
{0x48c1ac, "Plantronics"}
{0x48c862, "Simo Wireless"}
{0x48c8b6, "SysTec GmbH"}
{0x48cb6e, "Cello Electronics (UK)"}
{0x48d54c, "Jeda Networks"}
{0x48d7ff, "Blankom Antennentechnik Gmbh"}
{0x48d8fe, "ClarIDy Solutions"}
{0x48dcfb, "Nokia"}
{0x48df1c, "Wuhan NEC Fibre Optic Communications industry Co."}
{0x48e1af, "Vity"}
{0x48ea63, "Zhejiang Uniview Technologies Co."}
{0x48eb30, "Eterna Technology"}
{0x48ed80, "daesung eltec"}
{0x48f317, "Private"}
{0x48f47d, "TechVision Holding  Internation Limited"}
{0x48f7f1, "Alcatel-Lucent"}
{0x48f8e1, "Alcatel Lucent WT"}
{0x48fcb8, "Woodstream"}
{0x4c022e, "CMR Korea CO."}
{0x4c0289, "LEX Computech CO."}
{0x4c07c9, "Computer Office Co."}
{0x4c0f6e, "Hon Hai Precision Ind. Co."}
{0x4c1480, "Noregon Systems"}
{0x4c17eb, "Sagemcom"}
{0x4c1a3a, "Prima Research And Production Enterprise"}
{0x4c1fcc, "Huawei Technologies Co."}
{0x4c2c80, "Beijing Skyway Technologies Co."}
{0x4c2f9d, "ICM Controls"}
{0x4c3089, "Thales Transportation Systems GmbH"}
{0x4c322d, "Teledata Networks"}
{0x4c32d9, "M Rutty Holdings"}
{0x4c3910, "Newtek Electronics co."}
{0x4c3b74, "Vogtec(h.k.) Co."}
{0x4c4b68, "Mobile Device"}
{0x4c5499, "Huawei Device Co."}
{0x4c5585, "Hamilton Systems"}
{0x4c5dcd, "Oy Finnish Electric Vehicle Technologies"}
{0x4c5fd2, "Alcatel-Lucent"}
{0x4c60d5, "airPointe of New Hampshire"}
{0x4c60de, "Netgear"}
{0x4c63eb, "Application Solutions (Electronics and Vision)"}
{0x4c64d9, "Guangdong Leawin Group Co."}
{0x4c7367, "Genius Bytes Software Solutions GmbH"}
{0x4c73a5, "Kove"}
{0x4c774f, "Embedded Wireless Labs "}
{0x4c8093, "Intel Corporate"}
{0x4c8b55, "Grupo Digicon"}
{0x4c98ef, "Zeo"}
{0x4c9e80, "Kyokko Electric Co."}
{0x4c9ee4, "Hanyang Navicom Co."}
{0x4ca74b, "Alcatel Lucent"}
{0x4caa16, "AzureWave Technologies (Shanghai)"}
{0x4cac0a, "ZTE"}
{0x4cb16c, "Huawei Technologies Co."}
{0x4cb199, "Apple"}
{0x4cb4ea, "HRD (S) PTE."}
{0x4cb9c8, "Conet CO."}
{0x4cbaa3, "Bison Electronics"}
{0x4cc452, "Shang Hai Tyd. Electon Technology"}
{0x4cc602, "Radios"}
{0x4cc94f, "Alcatel-Lucent"}
{0x4ce676, "Buffalo"}
{0x4ceb42, "Intel Corporate"}
{0x4cedde, "Askey Computer"}
{0x4cf737, "SamJi Electronics Co."}
{0x50008c, "Hong Kong Telecommunications (HKT) Limited"}
{0x50053d, "CyWee Group"}
{0x500b32, "Foxda Technology Industrial(ShenZhen)Co."}
{0x500e6d, "TrafficCast International"}
{0x502267, "PixeLINK"}
{0x50252b, "Nethra Imaging Incorporated"}
{0x502690, "Fujitsu Limited"}
{0x502a7e, "Smart electronic GmbH"}
{0x502a8b, "Telekom Research and Development Sdn Bhd"}
{0x502d1d, "Nokia"}
{0x502da2, "Intel Corporate"}
{0x502df4, "Phytec Messtechnik GmbH"}
{0x503de5, "Cisco Systems"}
{0x504a5e, "Masimo"}
{0x505663, "Texas Instruments"}
{0x5057a8, "Cisco Systems"}
{0x506028, "Xirrus"}
{0x506313, "Hon Hai Precision Ind. Co."}
{0x506441, "Greenlee"}
{0x5067f0, "ZyXEL Communications"}
{0x506f9a, "Wi-Fi Alliance"}
{0x5070e5, "He Shan World Fair Electronics Technology Limited"}
{0x50795b, "Interexport Telecomunicaciones S.A."}
{0x507d02, "Biodit"}
{0x5087b8, "Nuvyyo"}
{0x508a42, "Uptmate Technology Co."}
{0x508acb, "Shenzhen Maxmade Technology CO."}
{0x50934f, "Gradual Tecnologia Ltda."}
{0x509772, "Westinghouse Digital"}
{0x50a6e3, "David Clark Company"}
{0x50a733, "Ruckus Wireless"}
{0x50af73, "Shenzhen Bitland Information Technology Co."}
{0x50c58d, "Juniper Networks"}
{0x50c971, "GN Netcom A/S"}
{0x50ccf8, "Samsung Electro Mechanics"}
{0x50ce75, "Measy Electronics"}
{0x50d274, "Steffes"}
{0x50d6d7, "Takahata Precision"}
{0x50e549, "Giga-byte Technology Co."}
{0x50ead6, "Apple"}
{0x50eb1a, "Brocade Communications Systems"}
{0x50ed94, "Egatel SL"}
{0x50f003, "Open Stack"}
{0x50f61a, "Kunshan Jade Technologies co."}
{0x50faab, "L-tek d.o.o."}
{0x50fc30, "Treehouse Labs"}
{0x5403f5, "EBN Technology"}
{0x540496, "Gigawave"}
{0x5404a6, "Asustek Computer"}
{0x54055f, "Alcatel Lucent"}
{0x541dfb, "Freestyle Energy"}
{0x542018, "Tely Labs"}
{0x542a9c, "LSY Defense"}
{0x543131, "Raster Vision"}
{0x5435df, "Symeo GmbH"}
{0x544249, "Sony"}
{0x544a05, "wenglor sensoric gmbh"}
{0x5453ed, "Sony"}
{0x545fa9, "Teracom Limited"}
{0x5475d0, "Cisco Systems"}
{0x547f54, "Ingenico"}
{0x547fee, "Cisco Systems"}
{0x54847b, "Digital Devices GmbH"}
{0x548922, "Zelfy"}
{0x548998, "Huawei Technologies Co."}
{0x5492be, "Samsung Electronics Co."}
{0x549478, "Silvershore Technology Partners"}
{0x549a16, "Uzushio Electric Co."}
{0x549b12, "Samsung Electronics"}
{0x54a51b, "Huawei Device Co."}
{0x54a9d4, "Minibar Systems"}
{0x54b620, "Suhdol E&Cltd."}
{0x54cda7, "Fujian Shenzhou Electronic Co."}
{0x54d0ed, "Axim Communications"}
{0x54d46f, "Cisco Spvtg"}
{0x54e63f, "ShenZhen LingKeWeiEr Technology Co."}
{0x54e6fc, "Tp-link Technologies CO."}
{0x54f5b6, "Oriental Pacific International Limited"}
{0x54fdbf, "Scheidt & Bachmann GmbH"}
{0x580556, "Elettronica GF S.r.L."}
{0x5808fa, "Fiber Optic &amp; telecommunication"}
{0x581626, "Avaya"}
{0x58170c, "Sony Ericsson Mobile Communications AB"}
{0x581d91, "Advanced Mobile Telecom co."}
{0x581faa, "Apple"}
{0x581fef, "Tuttnaer"}
{0x582efe, "Lighting Science Group"}
{0x582f42, "Universal Electric"}
{0x5835d9, "Cisco Systems"}
{0x583cc6, "Omneality"}
{0x5842e4, "Sigma International General Medical Apparatus"}
{0x5846e1, "Baxter Healthcare"}
{0x5848c0, "Coflec"}
{0x5849ba, "Chitai Electronic"}
{0x584c19, "Chongqing Guohong Technology Development Company Limited"}
{0x584cee, "Digital One Technologies, Limited"}
{0x585076, "Linear Equipamentos Eletronicos SA"}
{0x5850e6, "Best Buy"}
{0x5855ca, "Apple"}
{0x58570d, "Danfoss Solar Inverters"}
{0x5866ba, "Hangzhou H3C Technologies Co., Limited"}
{0x58671a, "Barnes&noble.com"}
{0x58677f, "Clare Controls"}
{0x586d8f, "Cisco-Linksys"}
{0x586ed6, "Private"}
{0x587521, "Cjsc Rtsoft"}
{0x587675, "Beijing Echo Technologies Co."}
{0x587fc8, "S2M"}
{0x588d09, "Cisco Systems"}
{0x5891cf, "Intel Corporate"}
{0x58920d, "Kinetic Avionics Limited"}
{0x589396, "Ruckus Wireless"}
{0x58946b, "Intel Corporate"}
{0x589835, "Technicolor"}
{0x58a76f, "iD"}
{0x58b035, "Apple"}
{0x58b0d4, "ZuniData Systems"}
{0x58b9e1, "Crystalfontz America"}
{0x58bc27, "Cisco Systems"}
{0x58bda3, "Nintendo Co."}
{0x58d08f, "Ieee 1904.1 Working Group"}
{0x58db8d, "Fast Co."}
{0x58e476, "Centron Communications Technologies Fujian Co."}
{0x58e636, "EVRsafe Technologies"}
{0x58e747, "Deltanet AG"}
{0x58e808, "Autonics"}
{0x58eece, "Icon Time Systems"}
{0x58f67b, "Xia Men UnionCore Technology"}
{0x58f6bf, "Kyoto University"}
{0x58f98e, "Secudos Gmbh"}
{0x58fd20, "Bravida Sakerhet AB"}
{0x5c076f, "Thought Creator"}
{0x5c0a5b, "Samsung Electro-mechanics CO."}
{0x5c0cbb, "Celizion"}
{0x5c0e8b, "Motorola"}
{0x5c1437, "Thyssenkrupp Aufzugswerke GmbH"}
{0x5c16c7, "Big Switch Networks"}
{0x5c17d3, "LGE"}
{0x5c18b5, "Talon Communications"}
{0x5c260a, "Dell"}
{0x5c338e, "Alpha Networkc"}
{0x5c353b, "Compal Broadband Networks"}
{0x5c35da, "There Oy"}
{0x5c4058, "Jefferson Audio Video Systems"}
{0x5c4ca9, "Huawei Device Co."}
{0x5c5015, "Cisco Systems"}
{0x5c56ed, "3pleplay Electronics Private Limited"}
{0x5c57c8, "Nokia"}
{0x5c5948, "Apple"}
{0x5c5eab, "Juniper Networks"}
{0x5c63bf, "Tp-link Technologies CO."}
{0x5c6984, "Nuvico"}
{0x5c6a7d, "Kentkart EGE Elektronik SAN. VE TIC. STI."}
{0x5c6b32, "Texas Instruments"}
{0x5c6d20, "Hon Hai Precision Ind. Co."}
{0x5c6f4f, "S.A. Sistel"}
{0x5c7757, "Haivision Network Video"}
{0x5c864a, "Secret Labs"}
{0x5c8778, "Cybertelbridge co."}
{0x5c9ad8, "Fujitsu Limited"}
{0x5cac4c, "Hon Hai Precision Ind. Co."}
{0x5cb524, "Sony Ericsson Mobile Communications AB"}
{0x5cbd9e, "Hongkong Miracle Eagle Technology(group) Limited"}
{0x5cc213, "Fr. Sauter AG"}
{0x5cc6d0, "Skyworth Digital technology(shenzhen)co.ltd."}
{0x5cc9d3, "Palladium Energy Eletronica DA Amazonia Ltda"}
{0x5cca32, "Theben AG"}
{0x5ccead, "Cdyne"}
{0x5cd135, "Xtreme Power Systems"}
{0x5cd4ab, "Zektor"}
{0x5cd998, "D-Link"}
{0x5cdad4, "Murata Manufacturing Co."}
{0x5ce223, "Delphin Technology AG"}
{0x5ce286, "Nortel Networks"}
{0x5ceb4e, "R. Stahl HMI Systems Gmbh"}
{0x5cf207, "Speco Technologies"}
{0x5cf3fc, "IBM"}
{0x5cf9dd, "Dell"}
{0x5cff35, "Wistron"}
{0x601199, "Data-Tester"}
{0x601283, "Soluciones Tecnologicas para la Salud y el Bienestar SA"}
{0x6015c7, "IdaTech"}
{0x60190c, "Rramac"}
{0x601d0f, "Midnite Solar"}
{0x602a54, "CardioTek B.V."}
{0x602ad0, "Cisco Spvtg"}
{0x60334b, "Apple"}
{0x603553, "Buwon Technology"}
{0x6036dd, "Intel Corporate"}
{0x60380e, "Alps Electric Co.,"}
{0x60391f, "ABB"}
{0x603fc5, "COX CO."}
{0x6044f5, "Easy Digital"}
{0x6052d0, "Facts Engineering"}
{0x605464, "Eyedro Green Solutions"}
{0x6063fd, "Transcend Communication Beijing Co."}
{0x606720, "Intel Corporate"}
{0x606bbd, "Samsung Electronics Co."}
{0x606c66, "Intel Corporate"}
{0x607688, "Velodyne"}
{0x6083b2, "GkWare e.K."}
{0x608645, "Avery Weigh-Tronix"}
{0x60893c, "Thermo Fisher Scientific P.O.A."}
{0x6089b7, "Kael Mhendislik Elektronik Ticaret Sanayi Limited irketi"}
{0x608c2b, "Hanson Technology"}
{0x608d17, "Sentrus Government Systems Division"}
{0x609aa4, "GVI Security"}
{0x609e64, "Vivonic GmbH"}
{0x609f9d, "CloudSwitch"}
{0x60a10a, "Samsung Electronics Co."}
{0x60b3c4, "Elber Srl"}
{0x60b606, "Phorus"}
{0x60c547, "Apple"}
{0x60c980, "Trymus"}
{0x60d0a9, "Samsung Electronics Co."}
{0x60d30a, "Quatius Limited"}
{0x60d819, "Hon Hai Precision Ind. Co."}
{0x60da23, "Estech Co."}
{0x60e956, "Ayla Networks"}
{0x60eb69, "Quanta computer"}
{0x60f13d, "Jablocom S.r.o."}
{0x60f281, "Tranwo Technology CO."}
{0x60f3da, "Logic Way GmbH"}
{0x60f59c, "CRU-Dataport"}
{0x60f673, "Terumo"}
{0x60facd, "Apple"}
{0x60fb42, "Apple"}
{0x6400f1, "Cisco Systems"}
{0x64094c, "Beijing Superbee Wireless Technology Co."}
{0x640e36, "Taztag"}
{0x640f28, "2wire"}
{0x641084, "Hexium Technical Development Co."}
{0x64168d, "Cisco Systems"}
{0x6416f0, "Shehzhen Huawei Communication Technologies Co."}
{0x641a22, "Heliospectra/Woodhill Investments"}
{0x641e81, "Dowslake Microsystems"}
{0x64200c, "Apple"}
{0x642400, "Xorcom"}
{0x642737, "Hon Hai Precision Ind. Co."}
{0x642db7, "Seungil Electronics"}
{0x643150, "Hewlett-Packard Company"}
{0x64317e, "Dexin"}
{0x643409, "BITwave Pte"}
{0x644346, "GuangDong Quick Network Computer CO."}
{0x644bc3, "Shanghai Woasis Telecommunications"}
{0x644bf0, "CalDigit"}
{0x644d70, "dSPACE GmbH"}
{0x644f74, "Lenus Co."}
{0x645299, "Chamberlain"}
{0x645422, "Equinox Payments"}
{0x645563, "Intelight"}
{0x64557f, "Nsfocus Information Technology Co."}
{0x645dd7, "Shenzhen Lifesense Medical Electronics Co.,"}
{0x645ebe, "Yahoo! Japan"}
{0x6465c0, "Nuvon"}
{0x646707, "Beijing Omnific Technology"}
{0x64680c, "Comtrend"}
{0x6469bc, "Hytera Communications Co"}
{0x646e6c, "Radio Datacom"}
{0x647002, "Tp-link Technologies CO."}
{0x6473e2, "Arbiter Systems"}
{0x647bd4, "Texas Instruments"}
{0x647d81, "Yokota Industrial Co"}
{0x647fda, "Tektelic Communications"}
{0x64808b, "VG Controls"}
{0x648099, "Intel"}
{0x648125, "Alphatron Marine BV"}
{0x648788, "Juniper Networks"}
{0x6487d7, "ADB Broadband Italia"}
{0x64995d, "LGE"}
{0x649b24, "V Technology Co."}
{0x649c8e, "Texas Instruments"}
{0x649ef3, "Cisco Systems"}
{0x64a0e7, "Cisco Systems"}
{0x64a232, "OOO Samlight"}
{0x64a769, "HTC"}
{0x64a837, "Juni Korea Co."}
{0x64ae0c, "Cisco Systems"}
{0x64ae88, "Polytec GmbH"}
{0x64b64a, "ViVOtech"}
{0x64b9e8, "Apple"}
{0x64bc11, "CombiQ AB"}
{0x64c5aa, "South African Broadcasting"}
{0x64c6af, "Axerra Networks"}
{0x64d02d, "Draytek France"}
{0x64d1a3, "Sitecom Europe BV"}
{0x64d241, "Keith & Koep GmbH"}
{0x64d4da, "Intel Corporate"}
{0x64d912, "Solidica"}
{0x64d989, "Cisco Systems"}
{0x64db18, "OpenPattern"}
{0x64dc01, "Static Systems Group PLC"}
{0x64de1c, "Kingnetic Pte"}
{0x64e161, "DEP"}
{0x64e682, "Apple"}
{0x64e84f, "Serialway Communication Technology Co."}
{0x64e8e6, "global moisture management system"}
{0x64ed57, "Motorola Mobility"}
{0x64ed62, "Woori Systems Co."}
{0x64f970, "Kenade Electronics Technology Co."}
{0x64f987, "Avvasi"}
{0x64fc8c, "Zonar Systems"}
{0x6805ca, "Intel"}
{0x680927, "Apple"}
{0x68122d, "Special Instrument Development Co."}
{0x681605, "Systems And Electronic Development Fzco"}
{0x681ab2, "zte"}
{0x681fd8, "Advanced Telemetry"}
{0x68234b, "Nihon Dengyo Kousaku"}
{0x684352, "Bhuu Limited"}
{0x684b88, "Galtronics Telemetry"}
{0x6854f5, "enLighted"}
{0x68597f, "Alcatel Lucent"}
{0x685b36, "Powertech Industrial CO."}
{0x685d43, "Intel Corporate"}
{0x685e6b, "PowerRay Co."}
{0x686359, "Advanced Digital Broadcast SA"}
{0x686e23, "Wi3"}
{0x68784c, "Nortel Networks"}
{0x687924, "ELS-GmbH & Co. KG"}
{0x6879ed, "Sharp"}
{0x687f74, "Cisco-Linksys"}
{0x688470, "eSSys Co."}
{0x688540, "IGI Mobile"}
{0x68876b, "INQ Mobile Limited"}
{0x689234, "Ruckus Wireless"}
{0x68974b, "Shenzhen Costar Electronics Co."}
{0x689c5e, "AcSiP Technology"}
{0x68a1b7, "Honghao Mingchuan Technology (Beijing) CO."}
{0x68a3c4, "Liteon Technology"}
{0x68a86d, "Apple"}
{0x68aad2, "Datecs,"}
{0x68b599, "Hewlett-Packard Company"}
{0x68bc0c, "Cisco Systems"}
{0x68bdab, "Cisco Systems"}
{0x68ca00, "Octopus Systems Limited"}
{0x68cc9c, "Mine Site Technologies"}
{0x68cd0f, "U Tek Company Limited"}
{0x68d925, "ProSys Development Services"}
{0x68db96, "Opwill Technologies CO"}
{0x68dce8, "PacketStorm Communications"}
{0x68e41f, "Unglaube Identech GmbH"}
{0x68ebae, "Samsung Electronics Co."}
{0x68ebc5, "Angstrem Telecom"}
{0x68ed43, "Research In Motion"}
{0x68efbd, "Cisco Systems"}
{0x68f125, "Data Controls"}
{0x68f895, "Redflow Limited"}
{0x6c0460, "RBH Access Technologies"}
{0x6c0e0d, "Sony Ericsson Mobile Communications AB"}
{0x6c0f6a, "JDC Tech Co."}
{0x6c1811, "Decatur Electronics"}
{0x6c22ab, "Ainsworth Game Technology"}
{0x6c23b9, "Sony Ericsson Mobile Communications AB"}
{0x6c2e33, "Accelink Technologies Co."}
{0x6c2e85, "Sagemcom"}
{0x6c32de, "Indieon Technologies Pvt."}
{0x6c33a9, "Magicjack LP"}
{0x6c391d, "Beijing ZhongHuaHun Network Information center"}
{0x6c3a84, "Shenzhen Aero-Startech.Ltd"}
{0x6c3e9c, "KE Knestel Elektronik GmbH"}
{0x6c504d, "Cisco Systems"}
{0x6c5cde, "SunReports"}
{0x6c5d63, "ShenZhen Rapoo Technology Co."}
{0x6c5e7a, "Ubiquitous Internet Telecom Co."}
{0x6c626d, "Micro-Star INT'L CO."}
{0x6c6f18, "Stereotaxis"}
{0x6c7039, "Novar GmbH "}
{0x6c81fe, "Mitsuba"}
{0x6c8336, "Samsung Electronics Co."}
{0x6c8cdb, "Otus Technologies"}
{0x6c8d65, "Wireless Glue Networks"}
{0x6c92bf, "Inspur Electronic Information Industry Co."}
{0x6c9b02, "Nokia"}
{0x6c9ce9, "Nimble Storage"}
{0x6c9ced, "Cisco Systems"}
{0x6ca682, "Edam Information & Communications"}
{0x6ca780, "Nokia"}
{0x6ca906, "Telefield"}
{0x6ca96f, "TransPacket AS"}
{0x6cab4d, "Digital Payment Technologies"}
{0x6cac60, "Venetex"}
{0x6cad3f, "Hubbell Building Automation"}
{0x6cae8b, "IBM"}
{0x6cbee9, "Alcatel-Lucent-IPD"}
{0x6cc1d2, "Motorola Mobility"}
{0x6cc26b, "Apple"}
{0x6cd68a, "LG Electronics"}
{0x6cdc6a, "Promethean Limited"}
{0x6ce0b0, "Sound4"}
{0x6ce907, "Nokia"}
{0x6cf049, "Giga-byte Technology Co."}
{0x6cf37f, "Aruba Networks"}
{0x6cfdb9, "Proware Technologies Co"}
{0x6cffbe, "MPB Communications"}
{0x700258, "01db-metravib"}
{0x700514, "LG Electronics"}
{0x701404, "Limited Liability Company "Research Center "Bresler""}
{0x701a04, "Liteon Tech"}
{0x701aed, "Advas CO."}
{0x702b1d, "E-Domus International Limited"}
{0x702f97, "Aava Mobile Oy"}
{0x703187, "ACX GmbH"}
{0x7032d5, "Athena Wireless Communications"}
{0x7038ee, "Avaya"}
{0x703ad8, "Shenzhen Afoundry Electronic Co."}
{0x703c39, "Seawing Kft"}
{0x7041b7, "Edwards Lifesciences"}
{0x704642, "Chyng Hong Electronic CO."}
{0x704aae, "Xstream Flow (Pty)"}
{0x705812, "Panasonic AVC Networks Company"}
{0x705ab6, "Compal Information (kunshan) CO."}
{0x705cad, "Konami Gaming"}
{0x705eaa, "Action Target"}
{0x706417, "Orbis Tecnologia Electrica S.A."}
{0x706582, "Suzhou Hanming Technologies Co."}
{0x706f81, "Private"}
{0x70704c, "Purple Communications"}
{0x7071bc, "Pegatron"}
{0x7072cf, "EdgeCore Networks"}
{0x7073cb, "Apple"}
{0x7076f0, "LevelOne Communications (India) Private Limited"}
{0x707be8, "Huawei Technologies Co."}
{0x707e43, "Motorola Mobility"}
{0x707ede, "Nastec"}
{0x708105, "Cisco Systems"}
{0x70828e, "OleumTech"}
{0x708b78, "citygrow technology co."}
{0x709756, "Happyelectronics Co."}
{0x709e86, "X6D Limited"}
{0x70a191, "Trendsetter Medical"}
{0x70a41c, "Advanced Wireless Dynamics S.L."}
{0x70a66a, "Prox Dynamics AS"}
{0x70aab2, "Research In Motion"}
{0x70b035, "Shenzhen Zowee Technology Co."}
{0x70b08c, "Shenou Communication Equipment Co."}
{0x70b265, "Hiltron s.r.l."}
{0x70b921, "FiberHome Telecommunication Technologies CO."}
{0x70ca9b, "Cisco Systems"}
{0x70cd60, "Apple"}
{0x70d4f2, "RIM"}
{0x70d57e, "Scalar"}
{0x70d5e7, "Wellcore"}
{0x70d6b6, "Metrum Technologies"}
{0x70d880, "Upos System sp. z o.o."}
{0x70dda1, "Tellabs"}
{0x70dee2, "Apple"}
{0x70e139, "3view"}
{0x70e843, "Beijing C&W Optical Communication Technology Co."}
{0x70ee50, "Netatmo"}
{0x70f1a1, "Liteon Technology"}
{0x70f395, "Universal Global Scientific Industrial Co."}
{0x740abc, "Jsjs Designs (europe) Limited"}
{0x7415e2, "Tri-Sen Systems"}
{0x742b0f, "Infinidat"}
{0x742f68, "Azurewave Technologies"}
{0x743170, "Arcadyan Technology"}
{0x743256, "NT-ware Systemprg GmbH"}
{0x743889, "Annax Anzeigesysteme Gmbh"}
{0x744401, "Netgear"}
{0x745612, "Motorola Mobility"}
{0x745798, "Trumpf Laser Gmbh + Co. KG"}
{0x745e1c, "Pioneer"}
{0x7463df, "VTS GmbH"}
{0x7465d1, "Atlinks"}
{0x746b82, "Movek"}
{0x7472f2, "Chipsip Technology Co."}
{0x747818, "ServiceAssure"}
{0x747b7a, "ETH"}
{0x747db6, "Aliwei Communications"}
{0x747e1a, "Red Embedded Design Limited"}
{0x747e2d, "Beijing Thomson Citic Digital Technology Co."}
{0x748ef8, "Brocade Communications Systems"}
{0x749050, "Renesas Electronics"}
{0x74911a, "Ruckus Wireless"}
{0x74a4a7, "QRS Music Technologies"}
{0x74a722, "LG Electronics"}
{0x74b00c, "Network Video Technologies"}
{0x74b9eb, "Fujian JinQianMao Electronic Technology Co."}
{0x74be08, "Atek Products"}
{0x74cd0c, "Smith Myers Communications"}
{0x74ce56, "Packet Force Technology Limited Company"}
{0x74d0dc, "Ericsson AB"}
{0x74d675, "Wyma Tecnologia"}
{0x74d850, "Evrisko Systems"}
{0x74de2b, "Liteon Technology"}
{0x74e06e, "Ergophone GmbH"}
{0x74e1b6, "Apple"}
{0x74e50b, "Intel Corporate"}
{0x74e537, "Radspin"}
{0x74e7c6, "Motorola Mobility"}
{0x74ea3a, "Tp-link Technologies Co."}
{0x74f06d, "AzureWave Technologies"}
{0x74f07d, "BnCOM Co."}
{0x74f612, "Motorola Mobility"}
{0x74f726, "Neuron Robotics"}
{0x74fda0, "Compupal (Group) "}
{0x74ff7d, "Wren Sound Systems"}
{0x78028f, "Adaptive Spectrum and Signal Alignment (assia)"}
{0x780738, "Z.U.K. Elzab S.A."}
{0x781185, "NBS Payment Solutions"}
{0x7812b8, "Orantek Limited"}
{0x78192e, "Nascent Technology"}
{0x7819f7, "Juniper Networks"}
{0x781c5a, "Sharp"}
{0x781dba, "Huawei Technologies Co."}
{0x781dfd, "Jabil"}
{0x78223d, "Affirmed Networks"}
{0x7825ad, "Samsung Electronics CO."}
{0x782bcb, "Dell"}
{0x782eef, "Nokia"}
{0x7830e1, "UltraClenz"}
{0x783f15, "EasySYNC"}
{0x784476, "Zioncom technology co."}
{0x7845c4, "Dell"}
{0x78471d, "Samsung Electronics Co."}
{0x78510c, "LiveU"}
{0x785712, "Mobile Integration Workgroup"}
{0x78593e, "Rafi Gmbh &KG"}
{0x785c72, "Hioso Technology Co."}
{0x7866ae, "Ztec Instruments"}
{0x787f62, "GiK mbH"}
{0x78818f, "Server Racks Australia"}
{0x78843c, "Sony"}
{0x7884ee, "Indra Espacio S.A."}
{0x788973, "CMC"}
{0x788c54, "Enkom Technologies"}
{0x78929c, "Intel Corporate"}
{0x78998f, "Mediline Italia SRL"}
{0x78a051, "iiNet Labs "}
{0x78a183, "Advidia"}
{0x78a2a0, "Nintendo Co."}
{0x78a3e4, "Apple"}
{0x78a5dd, "Shenzhen Smarteye Digital Electronics Co."}
{0x78a683, "Precidata"}
{0x78a6bd, "Daeyeon Control&instrument Co"}
{0x78a714, "Amphenol"}
{0x78acc0, "Hewlett-Packard Company"}
{0x78b6c1, "Aobo Telecom Co."}
{0x78b81a, "Inter Sales A/S"}
{0x78bad0, "Shinybow Technology Co."}
{0x78beb6, "Enhanced Vision"}
{0x78c40e, "H&D Wireless "}
{0x78c6bb, "Innovasic"}
{0x78ca04, "Nokia"}
{0x78ca39, "Apple"}
{0x78cd8e, "SMC Networks"}
{0x78d004, "Neousys Technology"}
{0x78d6f0, "Samsung Electro Mechanics"}
{0x78dd08, "Hon Hai Precision Ind. Co."}
{0x78ddd6, "c-scape"}
{0x78dee4, "Texas Instruments"}
{0x78e3b5, "Hewlett-Packard Company"}
{0x78e400, "Hon Hai Precision Ind. Co."}
{0x78e7d1, "Hewlett-Packard Company"}
{0x78ec22, "Shanghai Qihui Telecom Technology Co."}
{0x78ef4c, "Unetconvergence Co."}
{0x78f7d0, "Silverbrook Research"}
{0x78fe3d, "Juniper Networks"}
{0x7c034c, "Sagemcom"}
{0x7c051e, "Rafael"}
{0x7c08d9, "Shanghai Engineering Research Center for Broadband Technologies and Applications"}
{0x7c11be, "Apple"}
{0x7c1476, "Damall TechnologiesS. Di Ludovic Anselme Glaglanon & C."}
{0x7c1e52, "Microsoft"}
{0x7c1eb3, "2N Telekomunikace a.s."}
{0x7c2064, "Alcatel Lucent IPD"}
{0x7c2cf3, "Secure Electrans"}
{0x7c2e0d, "Blackmagic Design"}
{0x7c2f80, "Gigaset Communications GmbH"}
{0x7c336e, "MEG Electronics"}
{0x7c3920, "Ssoma Security"}
{0x7c3bd5, "Imago Group"}
{0x7c3e9d, "Patech"}
{0x7c4a82, "Portsmith"}
{0x7c4aa8, "MindTree Wireless PVT"}
{0x7c4b78, "Red Sun Synthesis Pte"}
{0x7c4c58, "Scale Computing"}
{0x7c4ca5, "BSkyB"}
{0x7c4fb5, "Arcadyan Technology"}
{0x7c55e7, "YSI"}
{0x7c6193, "HTC"}
{0x7c6adb, "SafeTone Technology Co."}
{0x7c6b33, "Tenyu Tech Co."}
{0x7c6b52, "Tigaro Wireless"}
{0x7c6c39, "Pixsys SRL"}
{0x7c6c8f, "AMS Neve"}
{0x7c6d62, "Apple"}
{0x7c6f06, "Caterpillar Trimble Control Technologies"}
{0x7c7673, "Enmas Gmbh"}
{0x7c7be4, "Z&#39;sedai Kenkyusho"}
{0x7c7d41, "Jinmuyu Electronics Co."}
{0x7c8ee4, "Texas Instruments"}
{0x7c94b2, "Philips Healthcare Pcci"}
{0x7ca29b, "D.SignT GmbH &amp; Co. KG"}
{0x7ca61d, "MHL"}
{0x7cacb2, "Bosch Software Innovations GmbH"}
{0x7cb03e, "Osram AG"}
{0x7cb542, "Aces Technology"}
{0x7cbb6f, "Cosco Electronics Co."}
{0x7cc3a1, "Apple"}
{0x7cc537, "Apple"}
{0x7cc8d7, "Damalisk"}
{0x7ccb0d, "Aaxeon Technologies"}
{0x7ccfcf, "Shanghai Seari Intelligent System Co."}
{0x7cda84, "Dongnian Networks"}
{0x7cdd11, "Chongqing MAS Sci&tech.co."}
{0x7cdd20, "Ioxos Technologies S.A."}
{0x7cdd90, "Shenzhen Ogemray Technology Co."}
{0x7ce044, "Neon"}
{0x7ce9d3, "Hon Hai Precision Ind. Co."}
{0x7ced8d, "Microsoft"}
{0x7cef18, "Creative Product Design"}
{0x7cef8a, "Inhon International"}
{0x7cf05f, "Apple"}
{0x7cf098, "Bee Beans Technologies"}
{0x7cf0ba, "Linkwell Telesystems Pvt"}
{0x7cf429, "Nuuo"}
{0x80000b, "Intel Corporate"}
{0x800010, "ATT Bell Laboratories"}
{0x800a06, "Comtec Co."}
{0x801440, "Sunlit System Technology"}
{0x8016b7, "Brunel University"}
{0x80177d, "Nortel Networks"}
{0x8018a7, "Samsung Eletronics Co."}
{0x801f02, "Edimax Technology Co."}
{0x8020af, "Trade Fides"}
{0x802275, "Beijing Beny Wave Technology Co"}
{0x802de1, "Solarbridge Technologies"}
{0x802e14, "azeti Networks AG"}
{0x803457, "OT Systems Limited"}
{0x8038fd, "LeapFrog Enterprises"}
{0x8039e5, "Patlite"}
{0x803b9a, "ghe-ces electronic ag"}
{0x803f5d, "Winstars Technology"}
{0x80427c, "Adolf Tedsen GmbH & Co. KG"}
{0x804731, "Packet Design"}
{0x804f58, "ThinkEco"}
{0x80501b, "Nokia"}
{0x8058c5, "NovaTec Kommunikationstechnik GmbH"}
{0x806007, "RIM"}
{0x806459, "Nimbus"}
{0x8065e9, "BenQ"}
{0x806629, "Prescope Technologies CO."}
{0x806cbc, "NET New Electronic Technology GmbH"}
{0x80711f, "Juniper Networks"}
{0x807693, "Newag SA"}
{0x807a7f, "ABB Genway Xiamen Electrical Equipment CO."}
{0x807d1b, "Neosystem Co."}
{0x807de3, "Chongqing Sichuan Instrument MicrocircuitLTD."}
{0x8081a5, "Tongqing Communication Equipment (shenzhen) Co."}
{0x808698, "Netronics Technologies"}
{0x80912a, "Lih Rong electronic Enterprise Co."}
{0x8091c0, "AgileMesh"}
{0x809393, "Xapt GmbH"}
{0x80946c, "Tokyo Radar"}
{0x80971b, "Altenergy Power System"}
{0x809b20, "Intel Corporate"}
{0x80a1d7, "Shanghai DareGlobal Technologies Co."}
{0x80b289, "Forworld Electronics"}
{0x80b32a, "Alstom Grid"}
{0x80b686, "Huawei Technologies Co."}
{0x80baac, "TeleAdapt"}
{0x80c16e, "Hewlett Packard"}
{0x80c63f, "Remec Broadband Wireless "}
{0x80c6ab, "Technicolor USA"}
{0x80c6ca, "Endian s.r.l."}
{0x80c862, "Openpeak"}
{0x80d019, "Embed"}
{0x80db31, "Power Quotient International Co."}
{0x80ee73, "Shuttle"}
{0x80f593, "Irco Sistemas de Telecomunicacin S.A."}
{0x80fb06, "Huawei Technologies Co."}
{0x80ffa8, "Unidis"}
{0x8400d2, "Sony Ericsson Mobile Communications AB"}
{0x841888, "Juniper Networks"}
{0x841b5e, "Netgear"}
{0x842141, "Shenzhen Ginwave Technologies"}
{0x84248d, "Motorola Solutions"}
{0x8425db, "Samsung Electronics Co."}
{0x8427ce, "Corporation of the Presiding Bishop of The Church of Jesus Christ of Latter-day Saints"}
{0x842914, "Emporia Telecom Produktions- und Vertriebsgesmbh & Co KG"}
{0x842b2b, "Dell"}
{0x842b50, "Huria Co."}
{0x8430e5, "SkyHawke Technologies"}
{0x843611, "hyungseul publishing networks"}
{0x843f4e, "Tri-Tech Manufacturing"}
{0x844823, "Woxter Technology Co."}
{0x844915, "vArmour Networks"}
{0x845787, "DVR C&C Co."}
{0x845dd7, "Shenzhen Netcom Electronics Co."}
{0x846aed, "Wireless Tsukamoto."}
{0x846eb1, "Park Assist"}
{0x84742a, "zte"}
{0x848d84, "Rajant"}
{0x848f69, "Dell"}
{0x849000, "Arnold &amp; Richter Cine Technik"}
{0x8497b8, "Memjet"}
{0x84a6c8, "Intel Corporate"}
{0x84a8e4, "Huawei Device Co."}
{0x84a991, "Cyber Trans Japan Co."}
{0x84af1f, "Beat System Service Co"}
{0x84c727, "Gnodal"}
{0x84c7a9, "C3po S.A."}
{0x84c9b2, "D-Link International"}
{0x84d32a, "Ieee P1905.1"}
{0x84d9c8, "Unipattern Co.,"}
{0x84db2f, "Sierra Wireless"}
{0x84de3d, "Crystal Vision"}
{0x84ea99, "Vieworks"}
{0x84f64c, "Cross Point BV"}
{0x8818ae, "Tamron Co."}
{0x882012, "LMI Technologies"}
{0x8821e3, "Nebusens"}
{0x8823fe, "TTTech Computertechnik AG"}
{0x88252c, "Arcadyan Technology"}
{0x88308a, "Murata Manufactuaring Co."}
{0x8841c1, "Orbisat DA Amazonia IND E Aerol SA"}
{0x8843e1, "Cisco Systems"}
{0x884b39, "Siemens AG, Healthcare Sector"}
{0x88532e, "Intel Corporate"}
{0x8853d4, "Huawei Technologies Co."}
{0x885c4f, "Alcatel Lucent"}
{0x886b76, "China Hopeful Group Hopeful Electric Co."}
{0x8886a0, "Simton Technologies"}
{0x888717, "Canon"}
{0x888b5d, "Storage Appliance "}
{0x888c19, "Brady Asia Pacific"}
{0x8891dd, "Racktivity"}
{0x8894f9, "Gemicom Technology"}
{0x8895b9, "Unified Packet Systems Crop"}
{0x8897df, "Entrypass Sdn. Bhd."}
{0x889821, "Teraon"}
{0x889ffa, "Hon Hai Precision Ind. Co."}
{0x88a5bd, "Qpcom"}
{0x88acc1, "Generiton Co."}
{0x88ae1d, "Compal Information(kunshan)co."}
{0x88b168, "Delta Control GmbH"}
{0x88b627, "Gembird Europe BV"}
{0x88ba7f, "Qfiednet Co."}
{0x88bfd5, "Simple Audio"}
{0x88c36e, "Beijing Ereneben lnformation Technology Limited"}
{0x88c663, "Apple"}
{0x88dd79, "Voltaire"}
{0x88e0a0, "Shenzhen VisionSTOR Technologies Co."}
{0x88e0f3, "Juniper Networks"}
{0x88e712, "Whirlpool"}
{0x88e7a6, "iKnowledge Integration"}
{0x88ed1c, "Cudo Communication Co."}
{0x88f077, "Cisco Systems"}
{0x88f488, "cellon communications technology(shenzhen)Co."}
{0x88fd15, "Lineeye CO."}
{0x8c0ca3, "Amper"}
{0x8c11cb, "Abus Security-center Gmbh & Co. KG"}
{0x8c1f94, "RF Surgical System "}
{0x8c210a, "Tp-link Technologies CO."}
{0x8c271d, "QuantHouse"}
{0x8c278a, "Vocollect"}
{0x8c4435, "Shanghai BroadMobi Communication Technology Co."}
{0x8c4dea, "Cerio"}
{0x8c5105, "Shenzhen ireadygo Information Technology CO."}
{0x8c53f7, "A&D Engineering CO."}
{0x8c541d, "LGE"}
{0x8c56c5, "Nintendo Co."}
{0x8c57fd, "LVX Western"}
{0x8c5877, "Apple"}
{0x8c598b, "C Technologies AB"}
{0x8c5ca1, "d-broad"}
{0x8c5fdf, "Beijing Railway Signal Factory"}
{0x8c604f, "Cisco Systems"}
{0x8c640b, "Beyond Devices d.o.o."}
{0x8c6422, "Sony Ericsson Mobile Communications AB"}
{0x8c6878, "Nortek-AS"}
{0x8c705a, "Intel Corporate"}
{0x8c71f8, "Samsung Electronics Co."}
{0x8c736e, "Fujitsu Limited"}
{0x8c7712, "Samsung Electronics Co."}
{0x8c7b9d, "Apple"}
{0x8c7cb5, "Hon Hai Precision Ind. Co."}
{0x8c7cff, "Brocade Communications Systems"}
{0x8c7eb3, "Lytro"}
{0x8c82a8, "Insigma Technology Co."}
{0x8c8401, "Private"}
{0x8c89a5, "Micro-Star INT'L CO."}
{0x8c8a6e, "Estun Automation Technoloy CO."}
{0x8c8e76, "taskit GmbH"}
{0x8c90d3, "Alcatel Lucent"}
{0x8c9236, "Aus.Linx Technology Co."}
{0x8c94cf, "Encell Technology"}
{0x8ca048, "Beijing NeTopChip Technology Co."}
{0x8ca982, "Intel Corporate"}
{0x8cb64f, "Cisco Systems"}
{0x8cb82c, "IPitomy Communications"}
{0x8cb864, "AcSiP Technology"}
{0x8cc121, "Panasonic AVC Networks Company"}
{0x8cc8cd, "Samsung Electronics Co."}
{0x8ccf5c, "Befega Gmbh"}
{0x8cd17b, "CG Mobile"}
{0x8cd628, "Ikor Metering"}
{0x8cdb25, "ESG Solutions"}
{0x8cdd8d, "Wifly-City System"}
{0x8cde52, "Issc Technologies"}
{0x8ce748, "Private"}
{0x8ce7b3, "Sonardyne International"}
{0x8cf9c9, "Mesada Technology Co."}
{0x90004e, "Hon Hai Precision Ind. Co."}
{0x90013b, "Sagemcom"}
{0x9002a9, "Zhejiang Dahua Technology Co."}
{0x9003b7, "Parrot"}
{0x900917, "Far-sighted mobile"}
{0x900a3a, "PSG Plastic Service GmbH"}
{0x900d66, "Digimore Electronics Co."}
{0x90185e, "Apex Tool Group GmbH & Co OHG"}
{0x9018ae, "Shanghai Meridian Technologies, Co."}
{0x901900, "SCS SA"}
{0x901b0e, "Fujitsu Technology Solutions GmbH"}
{0x902155, "HTC"}
{0x9027e4, "Apple"}
{0x902b34, "Giga-byte Technology Co."}
{0x902e87, "LabJack"}
{0x90342b, "Gatekeeper Systems"}
{0x9034fc, "Hon Hai Precision Ind. Co."}
{0x903aa0, "Alcatel-Lucent"}
{0x903cae, "Yunnan Ksec Digital Technology Co."}
{0x903d5a, "Shenzhen Wision Technology Holding Limited"}
{0x903d6b, "Zicon Technology"}
{0x904716, "Rorze"}
{0x904ce5, "Hon Hai Precision Ind. Co."}
{0x90507b, "Advanced Panmobil Systems Gmbh & Co. KG"}
{0x90513f, "Elettronica Santerno"}
{0x905446, "TES Electronic Solutions"}
{0x9055ae, "Ericsson, EAB/RWI/K"}
{0x905682, "Lenbrook Industries Limited"}
{0x905f8d, "modas GmbH"}
{0x90610c, "Fida International (S) Pte"}
{0x9067b5, "Alcatel-Lucent"}
{0x9067f3, "Alcatel Lucent"}
{0x906dc8, "DLG Automao Industrial Ltda"}
{0x906ebb, "Hon Hai Precision Ind. Co."}
{0x907f61, "Chicony Electronics Co."}
{0x90840d, "Apple"}
{0x9088a2, "Ionics Technology ME Ltda"}
{0x908d1d, "GH Technologies"}
{0x908fcf, "UNO System Co."}
{0x90903c, "Trison Technology"}
{0x909060, "RSI Video Technologies"}
{0x9092b4, "Diehl BGT Defence GmbH & Co. KG"}
{0x90a2da, "Gheo SA"}
{0x90a4de, "Wistron Neweb"}
{0x90a783, "JSW Pacific"}
{0x90a7c1, "Pakedge Device and Software"}
{0x90ac3f, "BrightSign"}
{0x90b134, "Motorola Mobility"}
{0x90b8d0, "Joyent"}
{0x90b97d, "Johnson Outdoors Marine Electronics d/b/a Minnkota"}
{0x90c115, "Sony Ericsson Mobile Communications AB"}
{0x90cf15, "Nokia"}
{0x90cf7d, "Qingdao Hisense Electric Co."}
{0x90d11b, "Palomar Medical Technologies"}
{0x90d74f, "Bookeen"}
{0x90d7eb, "Texas Instruments"}
{0x90d852, "Comtec Co."}
{0x90d92c, "Hug-witschi AG"}
{0x90e0f0, "Ieee P1722"}
{0x90e2ba, "Intel"}
{0x90e6ba, "Asustek Computer"}
{0x90ea60, "SPI Lasers "}
{0x90f278, "Radius Gateway"}
{0x90f4c1, "Rand McNally"}
{0x90f652, "Tp-link Technologies CO."}
{0x90f72f, "Phillips Machine & Welding Co."}
{0x90fb5b, "Avaya"}
{0x90fba6, "Hon Hai Precision Ind.Co.Ltd"}
{0x940070, "Nokia"}
{0x940149, "AutoHotBox"}
{0x940b2d, "NetView Technologies(Shenzhen) Co."}
{0x940c6d, "Tp-link Technologies Co."}
{0x9411da, "ITF Froschl GmbH"}
{0x941673, "Point Core Sarl"}
{0x941d1c, "TLab West Systems AB"}
{0x942053, "Nokia"}
{0x94236e, "Shenzhen Junlan Electronic"}
{0x942e17, "Schneider Electric Canada"}
{0x942e63, "Finscur"}
{0x94319b, "Alphatronics BV"}
{0x9433dd, "Taco Electronic Solutions"}
{0x9439e5, "Hon Hai Precision Ind. Co."}
{0x943af0, "Nokia"}
{0x944444, "LG Innotek"}
{0x944452, "Belkin International"}
{0x944696, "BaudTec"}
{0x945103, "Samsung Electronics"}
{0x94592d, "EKE Building Technology Systems"}
{0x945b7e, "Trilobit LTDA."}
{0x946124, "Pason Systems"}
{0x9463d1, "Samsung Electronics Co."}
{0x9471ac, "TCT Mobile Limited"}
{0x9481a4, "Azuray Technologies"}
{0x94857a, "Evantage Industries"}
{0x948854, "Texas Instruments"}
{0x948b03, "Eaget Innovation and Technology Co."}
{0x948d50, "Beamex Oy Ab"}
{0x948fee, "Hughes Telematics"}
{0x949c55, "Alta Data Technologies"}
{0x94a7bc, "BodyMedia"}
{0x94aab8, "Joview(Beijing) Technology Co."}
{0x94ae61, "Alcatel Lucent"}
{0x94ba31, "Visiontec da Amaznia Ltda."}
{0x94c4e9, "PowerLayer Microsystems HongKong Limited"}
{0x94c6eb, "Nova Electronics"}
{0x94c7af, "Raylios Technology"}
{0x94ca0f, "Honeywell Analytics"}
{0x94cdac, "Creowave Oy"}
{0x94d019, "Cydle"}
{0x94d723, "Shanghai DareGlobal Technologies Co."}
{0x94d93c, "Enelps"}
{0x94db49, "Sitcorp"}
{0x94dbc9, "Azurewave"}
{0x94dd3f, "A+V Link Technologies"}
{0x94de0e, "SmartOptics AS"}
{0x94df58, "IJ Electron CO."}
{0x94e0d0, "HealthStream Taiwan"}
{0x94e226, "D. ORtiz Consulting"}
{0x94e711, "Xirka Dama Persada PT"}
{0x94e848, "Fylde Micro"}
{0x94f692, "Geminico co."}
{0x94f720, "Tianjin Deviser Electronics Instrument Co."}
{0x94fae8, "Shenzhen Eycom Technology Co."}
{0x94fd1d, "WhereWhen"}
{0x94fef4, "Sagemcom"}
{0x980284, "Theobroma Systems GmbH"}
{0x9803a0, "ABB n.v. Power Quality Products"}
{0x9803d8, "Apple"}
{0x980c82, "Samsung Electro Mechanics"}
{0x980ee4, "Private"}
{0x98293f, "Fujian Start Computer Equipment Co."}
{0x982cbe, "2Wire"}
{0x982d56, "Resolution Audio"}
{0x983000, "Beijing Kemacom Technologies Co."}
{0x983571, "Sub10 Systems"}
{0x9835b8, "Assembled Products"}
{0x984246, "SOL Industry PTE."}
{0x984a47, "CHG Hospital Beds"}
{0x984b4a, "Motorola Mobility"}
{0x984be1, "Hewlett-Packard Company"}
{0x984e97, "Starlight Marketing (H. K.)"}
{0x98588a, "Sysgration"}
{0x985945, "Texas Instruments"}
{0x986022, "EMW Co."}
{0x9866ea, "Industrial Control Communications"}
{0x986dc8, "Toshiba Mitsubishi-electric Industrial Systems"}
{0x9873c4, "Sage Electronic Engineering"}
{0x988217, "Disruptive"}
{0x9889ed, "Anadem Information"}
{0x988b5d, "Sagem Communication"}
{0x988bad, "Corintech"}
{0x988e34, "Zhejiang Boxsam Electronic Co."}
{0x988edd, "Raychem International"}
{0x989080, "Linkpower Network System"}
{0x989449, "Skyworth Wireless Technology"}
{0x98aad7, "Blue Wave Networking CO"}
{0x98bc57, "SVA Technologiesltd"}
{0x98bc99, "Edeltech Co."}
{0x98c845, "PacketAccess"}
{0x98d6bb, "Apple"}
{0x98d88c, "Nortel Networks"}
{0x98dcd9, "Unitec Co."}
{0x98e165, "Accutome"}
{0x98e79a, "Foxconn(NanJing) Communication Co."}
{0x98ec65, "Cosesy ApS"}
{0x98f537, "zte"}
{0x98f8db, "Marini Impianti Industriali s.r.l."}
{0x98fc11, "Cisco-Linksys"}
{0x98fe03, "Ericsson - North America"}
{0x9c0111, "Shenzhen Newabel Electronic Co."}
{0x9c0298, "Samsung Electronics Co."}
{0x9c1874, "Nokia Danmark A/S"}
{0x9c1fdd, "Accupix"}
{0x9c220e, "Tascan Service Gmbh"}
{0x9c28bf, "Continental Automotive Czech Republic s.r.o."}
{0x9c31b6, "Kulite Semiconductor Products"}
{0x9c417c, "Hame  Technology Co.,  Limited "}
{0x9c4563, "Dimep Sistemas"}
{0x9c4a7b, "Nokia"}
{0x9c4e20, "Cisco Systems"}
{0x9c4e36, "Intel Corporate"}
{0x9c4e8e, "ALT Systems"}
{0x9c53cd, "Engicam S.r.l."}
{0x9c55b4, "I.S.E. S.r.l."}
{0x9c5711, "Feitian Xunda(Beijing) Aeronautical Information Technology Co."}
{0x9c5b96, "NMR"}
{0x9c5c8d, "Firemax Indstria E Comrcio DE Produtos Eletrnicos Ltda"}
{0x9c5d95, "VTC Electronics"}
{0x9c5e73, "Calibre UK"}
{0x9c645e, "Harman Consumer Group"}
{0x9c6abe, "Qees ApS."}
{0x9c7514, "Wildix srl"}
{0x9c77aa, "Nadasnv"}
{0x9c7bd2, "Neolab Convergence"}
{0x9c807d, "Syscable Korea"}
{0x9c8bf1, "The Warehouse Limited"}
{0x9c8e99, "Hewlett-Packard Company"}
{0x9c934e, "Xerox"}
{0x9c95f8, "SmartDoor Systems"}
{0x9ca134, "Nike"}
{0x9ca3ba, "Sakura Internet"}
{0x9cadef, "Obihai Technology"}
{0x9cafca, "Cisco Systems"}
{0x9cb008, "Ubiquitous Computing Technology"}
{0x9cb206, "Procentec"}
{0x9cb70d, "Liteon Technology"}
{0x9cc077, "PrintCounts"}
{0x9cc0d2, "Conductix-Wampfler AG"}
{0x9cc7d1, "Sharp"}
{0x9ccad9, "Nokia"}
{0x9ccd82, "Cheng UEI Precision Industry Co."}
{0x9cd24b, "zte"}
{0x9cdf03, "Harman/Becker Automotive Systems GmbH"}
{0x9ce10e, "NCTech"}
{0x9cebe8, "BizLink (Kunshan) Co."}
{0x9cf61a, "UTC Fire and Security"}
{0x9cf67d, "Ricardo Prague, s.r.o."}
{0x9cf938, "Areva NP Gmbh"}
{0x9cffbe, "Otsl"}
{0xa00798, "Samsung Electronics"}
{0xa007b6, "Advanced Technical Support"}
{0xa00bba, "Samsung Electro-mechanics"}
{0xa00ca1, "Sktb "skit""}
{0xa0133b, "Copyright  HiTi Digital"}
{0xa0165c, "TangoTec"}
{0xa01859, "Shenzhen Yidashi Electronics Co"}
{0xa021b7, "Netgear"}
{0xa0231b, "TeleComp R&amp;D"}
{0xa02ef3, "United Integrated Services Co."}
{0xa0369f, "Intel"}
{0xa036fa, "Ettus Research"}
{0xa03a75, "PSS Belgium N.V."}
{0xa04025, "Actioncable"}
{0xa04041, "Samwonfa Co."}
{0xa041a7, "NL Ministry of Defense"}
{0xa0423f, "Tyan Computer"}
{0xa04cc1, "Helixtech"}
{0xa04e04, "Nokia"}
{0xa055de, "Pace plc"}
{0xa0593a, "V.D.S. Video Display Systems srl"}
{0xa05aa4, "Grand Products Nevada"}
{0xa05dc1, "Tmct Co."}
{0xa05de7, "Directv"}
{0xa05e6b, "Melper Co."}
{0xa06986, "Wellav Technologies"}
{0xa06a00, "Verilink"}
{0xa06cec, "RIM"}
{0xa06d09, "Intelcan Technosystems"}
{0xa06e50, "Nanotek Elektronik Sistemler Sti."}
{0xa071a9, "Nokia"}
{0xa07332, "Cashmaster International Limited"}
{0xa07591, "Samsung Electronics Co."}
{0xa078ba, "Pantech Co."}
{0xa082c7, "P.T.I Co."}
{0xa086ec, "Saehan Hitec Co."}
{0xa088b4, "Intel Corporate"}
{0xa08c9b, "Xtreme Technologies"}
{0xa090de, "Veedims"}
{0xa09805, "OpenVox Communication Co"}
{0xa098ed, "Shandong Intelligent Optical Communication Development Co."}
{0xa09a5a, "Time Domain"}
{0xa0a763, "Polytron Vertrieb GmbH"}
{0xa0aafd, "EraThink Technologies"}
{0xa0b3cc, "Hewlett Packard"}
{0xa0b5da, "Hongkong Thtf Co."}
{0xa0b662, "Acutvista Innovation Co."}
{0xa0b9ed, "Skytap"}
{0xa0bfa5, "Coresys"}
{0xa0c3de, "Triton Electronic Systems"}
{0xa0cf5b, "Cisco Systems"}
{0xa0dc04, "Becker-Antriebe GmbH"}
{0xa0dde5, "Sharp"}
{0xa0de05, "JSC "Irbis-T""}
{0xa0e201, "AVTrace(China)"}
{0xa0e295, "DAT System Co."}
{0xa0e9db, "Ningbo FreeWings Technologies Co."}
{0xa0f217, "GE Medical System(China) Co."}
{0xa0f3c1, "Tp-link Technologies CO."}
{0xa0f3e4, "Alcatel -Lucent IPD"}
{0xa0f419, "Nokia"}
{0xa40130, "ABIsystems Co."}
{0xa40cc3, "Cisco Systems"}
{0xa4134e, "Luxul "}
{0xa41bc0, "Fastec Imaging"}
{0xa4218a, "Nortel Networks"}
{0xa424b3, "FlatFrog Laboratories AB"}
{0xa429b7, "bluesky"}
{0xa433d1, "Fibrlink Communications Co."}
{0xa438fc, "Plastic Logic"}
{0xa446fa, "AmTRAN Video"}
{0xa44b15, "Sun Cupid Technology (HK)"}
{0xa45055, "busware.de"}
{0xa4561b, "Mcot"}
{0xa45630, "Cisco Systems"}
{0xa45a1c, "smart-electronic GmbH"}
{0xa45c27, "Nintendo Co."}
{0xa46706, "Apple"}
{0xa479e4, "Klinfo"}
{0xa47aa4, "Motorola Mobility"}
{0xa47c14, "ChargeStorm AB"}
{0xa47c1f, "Global Microwave Systems"}
{0xa4856b, "Q Electronics"}
{0xa49005, "China Greatwall Computer Shenzhen Co."}
{0xa49981, "FuJian Elite Power Tech CO."}
{0xa49b13, "Burroughs Payment Systems"}
{0xa4a24a, "Cisco Spvtg"}
{0xa4a80f, "Shenzhen Coship Electronics Co."}
{0xa4ad00, "Ragsdale Technology"}
{0xa4adb8, "Vitec Group, Camera Dynamics"}
{0xa4ae9a, "Maestro Wireless Solutions"}
{0xa4b121, "Arantia 2010 S.L."}
{0xa4b197, "Apple"}
{0xa4b1ee, "H. Zander Gmbh & Co. KG"}
{0xa4b2a7, "Adaxys Solutions AG"}
{0xa4b36a, "JSC SDO Chromatec"}
{0xa4b980, "Parking Boxx"}
{0xa4badb, "Dell"}
{0xa4be61, "EutroVision System"}
{0xa4c0e1, "Nintendo Co."}
{0xa4c2ab, "Hangzhou Lead-it Information & Technology Co."}
{0xa4d1d1, "ECOtality North America"}
{0xa4d1d2, "Apple"}
{0xa4da3f, "Bionics"}
{0xa4db2e, "Kingspan Environmental"}
{0xa4de50, "Total Walther GmbH"}
{0xa4e32e, "Silicon &amp; Software Systems"}
{0xa4e391, "Deny Fontaine"}
{0xa4e7e4, "Connex GmbH"}
{0xa4ed4e, "Motorola Mobility"}
{0xa4ee57, "Seiko Epson"}
{0xa4ef52, "Telewave Co."}
{0xa4f7d0, "LAN Accessories Co."}
{0xa81758, "Elektronik System i Ume AB"}
{0xa81b18, "XTS"}
{0xa826d9, "HTC"}
{0xa83944, "Actiontec Electronics"}
{0xa84041, "Dragino Technology Co., Limited"}
{0xa849a5, "Lisantech Co."}
{0xa8556a, "Pocketnet Technology"}
{0xa85bb0, "Shenzhen Dehoo Technology Co."}
{0xa85bf3, "Audivo GmbH"}
{0xa862a2, "Jiwumedia CO."}
{0xa863df, "Displaire"}
{0xa863f2, "Texas Instruments"}
{0xa86a6f, "RIM"}
{0xa870a5, "UniComm"}
{0xa8776f, "Zonoff"}
{0xa87b39, "Nokia"}
{0xa87e33, "Nokia Danmark A/S"}
{0xa88792, "Broadband Antenna Tracking Systems"}
{0xa887ed, "ARC Wireless"}
{0xa88cee, "MicroMade Galka i Drozdz sp.j."}
{0xa8922c, "LG Electronics"}
{0xa893e6, "Jiangxi Jinggangshan Cking Communication Technology Co."}
{0xa898c6, "Shinbo Co."}
{0xa8995c, "aizo ag"}
{0xa89b10, "inMotion"}
{0xa8b0ae, "Leoni"}
{0xa8b1d4, "Cisco Systems"}
{0xa8bd1a, "Honey Bee (Hong Kong) Limited"}
{0xa8c222, "TM-Research"}
{0xa8cb95, "East Best CO."}
{0xa8ce90, "CVC"}
{0xa8d0e5, "Juniper Networks"}
{0xa8d3c8, "Wachendorff Elektronik  GmbH &amp; Co. KG"}
{0xa8e018, "Nokia"}
{0xa8e3ee, "Sony Computer Entertainment"}
{0xa8f274, "Samsung Electronics"}
{0xa8f470, "Fujian Newland Communication Science Technologies Co."}
{0xa8f94b, "Eltex Enterprise"}
{0xa8fcb7, "Consolidated Resource Imaging"}
{0xaa0000, "Digital Equipment"}
{0xaa0001, "Digital Equipment"}
{0xaa0002, "Digital Equipment"}
{0xaa0003, "Digital Equipment"}
{0xaa0004, "Digital Equipment"}
{0xac0142, "Uriel Technologies SIA"}
{0xac02cf, "RW Tecnologia Industria e Comercio Ltda"}
{0xac02ef, "Comsis"}
{0xac0613, "Senselogix"}
{0xac0dfe, "Ekon GmbH - myGEKKO"}
{0xac1461, "Ataw  Co."}
{0xac162d, "Hewlett Packard"}
{0xac199f, "Sungrow Power Supply Co."}
{0xac20aa, "Dmatek Co."}
{0xac2fa8, "Humannix Co."}
{0xac319d, "Shenzhen TG-NET Botone Technology Co."}
{0xac34cb, "Shanhai Gbcom Communication Technology Co."}
{0xac3d05, "Instorescreen Aisa"}
{0xac3d75, "Hangzhou Zhiway Technologies Co."}
{0xac3fa4, "Taiyo Yuden Co."}
{0xac40ea, "C&T Solution "}
{0xac44f2, "Revolabs"}
{0xac4723, "Genelec"}
{0xac4afe, "Hisense Broadband Multimedia Technology Co."}
{0xac4ffc, "Svs-vistek Gmbh"}
{0xac5135, "MPI Tech"}
{0xac51ee, "Cambridge Communication Systems"}
{0xac54ec, "Ieee P1823 Standards Working Group"}
{0xac583b, "Human Assembler"}
{0xac5e8c, "Utillink"}
{0xac6123, "Drivven"}
{0xac6706, "Ruckus Wireless"}
{0xac6f4f, "Enspert"}
{0xac6fbb, "Tatung Technology"}
{0xac6fd9, "Valueplus"}
{0xac7289, "Intel Corporate"}
{0xac80d6, "Hexatronic AB"}
{0xac8112, "Gemtek Technology Co."}
{0xac81f3, "Nokia"}
{0xac8317, "Shenzhen Furtunetel Communication Co."}
{0xac83f0, "Magenta Video Networks"}
{0xac8674, "Open Mesh"}
{0xac867e, "Create New Technology (HK) Limited Company"}
{0xac8acd, "Roger D.wensker, G.wensker sp.j."}
{0xac932f, "Nokia"}
{0xac9a96, "Lantiq Deutschland GmbH"}
{0xac9b84, "Smak Tecnologia e Automacao"}
{0xac9ce4, "Alcatel-Lucent Shanghai Bell Co."}
{0xaca016, "Cisco Systems"}
{0xacab8d, "Lyngso Marine A/S"}
{0xacbe75, "Ufine Technologies Co."}
{0xacbeb6, "Visualedge Technology Co."}
{0xacc935, "Ness"}
{0xacca54, "Telldus Technologies AB"}
{0xaccaba, "Midokura Co."}
{0xaccb09, "Hefcom Metering (Pty)"}
{0xaccc8e, "Axis Communications AB"}
{0xacce8f, "HWA YAO Technologies CO."}
{0xacd180, "Crexendo Business Solutions"}
{0xacd364, "ABB SPA, ABB Sace DIV."}
{0xacde48, "Private"}
{0xace348, "MadgeTech"}
{0xace87b, "Huawei Technologies Co."}
{0xace9aa, "Hay Systems"}
{0xacea6a, "Genix Infocomm CO."}
{0xacee3b, "6harmonics"}
{0xacf0b2, "Becker Electronics Taiwan"}
{0xacf97e, "Elesys"}
{0xb01b7c, "Ontrol A.S."}
{0xb01c91, "Elim Co"}
{0xb03829, "Siliconware Precision Industries Co."}
{0xb0487a, "Tp-link Technologies CO."}
{0xb0518e, "Holl technologyLtd."}
{0xb058c4, "Broadcast Microwave Services"}
{0xb05b1f, "Thermo Fisher Scientific S.p.a."}
{0xb05ce5, "Nokia"}
{0xb06563, "Shanghai Railway Communication Factory"}
{0xb06cbf, "3ality Digital Systems GmbH"}
{0xb075d5, "ZTE"}
{0xb07d62, "Dipl.-Ing. H. Horstmann GmbH"}
{0xb081d8, "I-sys"}
{0xb08991, "LGE"}
{0xb08e1a, "URadio Systems Co."}
{0xb09074, "Fulan Electronics Limited"}
{0xb09134, "Taleo"}
{0xb0973a, "E-Fuel"}
{0xb09928, "Fujitsu Limited"}
{0xb09ae2, "Stemmer Imaging Gmbh"}
{0xb09bd4, "GNH Software India Private Limited"}
{0xb0a10a, "Pivotal Systems"}
{0xb0a72a, "Ensemble Designs"}
{0xb0aa36, "Guangdong Oppo Mobile Telecommunications"}
{0xb0b32b, "Slican Sp. z o.o."}
{0xb0b8d5, "Nanjing Nengrui Auto Equipment CO."}
{0xb0bd6d, "Echostreams Innovative Solutions"}
{0xb0bda1, "Zaklad Elektroniczny Sims"}
{0xb0bf99, "Wizitdongdo"}
{0xb0c69a, "Juniper Networks"}
{0xb0c8ad, "People Power Company"}
{0xb0cf4d, "MI-Zone Technology Ireland"}
{0xb0d09c, "Samsung Electronics Co."}
{0xb0e39d, "CAT System Co."}
{0xb0e50e, "NRG Systems"}
{0xb0e754, "2Wire"}
{0xb0e892, "Seiko Epson"}
{0xb0e97e, "Advanced Micro Peripherals"}
{0xb0ec71, "Samsung Electronics Co."}
{0xb0f1bc, "Dhemax Ingenieros Ltda"}
{0xb40142, "GCI Science & Technology Co."}
{0xb40418, "Smartchip Integrated"}
{0xb407f9, "Samsung Electro-mechanics"}
{0xb40832, "TC Communications"}
{0xb40b7a, "Brusa Elektronik AG"}
{0xb40c25, "Palo Alto Networks"}
{0xb40e96, "Heran"}
{0xb40edc, "LG-Ericsson Co."}
{0xb41489, "Cisco Systems"}
{0xb41def, "Internet Laboratories"}
{0xb4211d, "Beijing GuangXin Technology Co."}
{0xb428f1, "E-Prime Co."}
{0xb42a39, "Orbit Merret, spol. s r. o."}
{0xb42cbe, "Direct Payment Solutions Limited"}
{0xb435f7, "Zhejiang Pearmain Electronicsltd."}
{0xb43741, "Consert"}
{0xb439d6, "ProCurve Networking by HP"}
{0xb43db2, "Degreane Horizon"}
{0xb4417a, "ShenZhen Gongjin Electronics Co."}
{0xb44cc2, "NR Electric CO."}
{0xb451f9, "NB Software"}
{0xb45253, "Seagate Technology"}
{0xb45570, "Borea"}
{0xb45861, "CRemote"}
{0xb45ca4, "Thing-talk Wireless Communication Technologies Limited"}
{0xb467e9, "Qingdao GoerTek Technology Co."}
{0xb4749f, "askey computer"}
{0xb48255, "Research Products"}
{0xb482fe, "Askey Computer"}
{0xb4944e, "WeTelecom Co."}
{0xb499ba, "Hewlett-Packard Company"}
{0xb49ee6, "Shenzhen Technology CO"}
{0xb4a4e3, "Cisco Systems"}
{0xb4a5a9, "Modi Gmbh"}
{0xb4aa4d, "Ensequence"}
{0xb4b017, "Avaya"}
{0xb4b362, "ZTE"}
{0xb4b5af, "Minsung Electronics"}
{0xb4b676, "Intel Corporate"}
{0xb4b88d, "Thuh Company"}
{0xb4c44e, "VXL eTech Pvt"}
{0xb4c799, "Motorola Solutions"}
{0xb4c810, "Umpi Elettronica"}
{0xb4cfdb, "Shenzhen Jiuzhou Electric Co."}
{0xb4d8a9, "BetterBots"}
{0xb4d8de, "iota Computing"}
{0xb4e0cd, "IO Turbine"}
{0xb4ed19, "Pie Digital"}
{0xb4ed54, "Wohler Technologies"}
{0xb4eed4, "Texas Instruments"}
{0xb4f323, "Petatel"}
{0xb4fc75, "Sema Electronics(hk) Co."}
{0xb80305, "Intel Corporate"}
{0xb80b9d, "Ropex Industrie-elektronik Gmbh"}
{0xb81413, "Keen High Holding(HK)"}
{0xb817c2, "Apple"}
{0xb81999, "Nesys"}
{0xb820e7, "Guangzhou Horizontal Information & Network Integration Co."}
{0xb826d4, "Furukawa Industrial S.A. Produtos Eltricos"}
{0xb827eb, "Raspberry Pi Foundation"}
{0xb8288b, "Parker Hannifin"}
{0xb82adc, "EFR Europische Funk-Rundsteuerung GmbH"}
{0xb82ca0, "Honeywell HomMed"}
{0xb83a7b, "Worldplay (Canada)"}
{0xb83d4e, "Shenzhen Cultraview Digital Technology Co.,Ltd Shanghai Branch"}
{0xb8415f, "ASP AG"}
{0xb85510, "Zioncom Electronics (Shenzhen)"}
{0xb8616f, "Accton Wireless Broadband(AWB)"}
{0xb8621f, "Cisco Systems"}
{0xb86491, "CK Telecom"}
{0xb8653b, "Bolymin"}
{0xb870f4, "Compal Information (kunshan) CO."}
{0xb87424, "Viessmann Elektronik GmbH"}
{0xb87447, "Convergence Technologies"}
{0xb8797e, "Secure Meters (UK) Limited"}
{0xb8871e, "Good Mind Industries Co."}
{0xb888e3, "Compal Information (kunshan) CO."}
{0xb88d12, "Apple"}
{0xb88e3a, "Infinite Technologies JLT"}
{0xb88f14, "Analytica GmbH"}
{0xb8921d, "BG T&amp;A"}
{0xb894d2, "Retail Innovation HTT AB"}
{0xb89674, "AllDSP GmbH &amp; Co. KG"}
{0xb8975a, "Biostar Microtech Int'l"}
{0xb89aed, "OceanServer Technology"}
{0xb89bc9, "SMC Networks"}
{0xb8a386, "D-Link International"}
{0xb8a3e0, "BenRui Technology Co."}
{0xb8a8af, "Logic S.p.A."}
{0xb8ac6f, "Dell"}
{0xb8af67, "Hewlett-Packard Company"}
{0xb8b1c7, "Bt&com Co."}
{0xb8b42e, "Gionee Communication Equipment Co,Ltd.ShenZhen"}
{0xb8ba68, "Xi'an Jizhong Digital Communication Co."}
{0xb8ba72, "Cynove"}
{0xb8bb6d, "Eneres Co."}
{0xb8bebf, "Cisco Systems"}
{0xb8c716, "Fiberhome Telecommunication Technologies Co."}
{0xb8c75d, "Apple"}
{0xb8cda7, "Maxeler Technologies"}
{0xb8d06f, "Guangzhou Hkust FOK Ying Tung Research Institute"}
{0xb8d49d, "M Seven System"}
{0xb8daf7, "Advanced Photonics"}
{0xb8e589, "Payter BV"}
{0xb8e625, "2Wire"}
{0xb8e779, "9Solutions Oy"}
{0xb8ee79, "YWire Technologies"}
{0xb8f4d0, "Herrmann Ultraschalltechnik GmbH & Co. Kg"}
{0xb8f5e7, "WayTools"}
{0xb8f6b1, "Apple"}
{0xb8f732, "Aryaka Networks"}
{0xb8f934, "Sony Ericsson Mobile Communications AB"}
{0xb8fd32, "Zhejiang Roicx Microelectronics"}
{0xb8ff61, "Apple"}
{0xb8ff6f, "Shanghai Typrotech TechnologyLtd"}
{0xb8fffe, "Texas Instruments"}
{0xbc0200, "Stewart Audio"}
{0xbc0543, "AVM GmbH"}
{0xbc0da5, "Texas Instruments"}
{0xbc0f2b, "Fortune Techgroup Co."}
{0xbc125e, "Beijing  WisVideo "}
{0xbc1401, "Hitron Technologies."}
{0xbc15a6, "Taiwan Jantek Electronics"}
{0xbc20ba, "Inspur (Shandong) Electronic Information Co."}
{0xbc2846, "NextBIT Computing Pvt."}
{0xbc2c55, "Bear Flag Design"}
{0xbc305b, "Dell"}
{0xbc35e5, "Hydro Systems Company"}
{0xbc38d2, "Pandachip Limited"}
{0xbc3e13, "Accordance Systems"}
{0xbc4377, "Hang Zhou Huite Technology Co."}
{0xbc4760, "Samsung Electronics Co."}
{0xbc4b79, "SensingTek"}
{0xbc4e3c, "Core Staff CO."}
{0xbc5ff4, "ASRock Incorporation"}
{0xbc6784, "Environics Oy"}
{0xbc6a16, "tdvine"}
{0xbc6e76, "Green Energy Options"}
{0xbc71c1, "XTrillion"}
{0xbc764e, "Rackspace US"}
{0xbc7670, "Huawei Device Co."}
{0xbc7737, "Intel Corporate"}
{0xbc779f, "SBM Co."}
{0xbc7dd1, "Radio Data Comms"}
{0xbc8199, "Basic Co."}
{0xbc83a7, "Shenzhen Chuangwei-rgb Electronics Co."}
{0xbc851f, "Samsung Electronics"}
{0xbc8b55, "NPP Eliks America DBA T&M Atlantic"}
{0xbc99bc, "FonSee Technology"}
{0xbc9da5, "Dascom Europe Gmbh"}
{0xbca4e1, "Nabto"}
{0xbca9d6, "Cyber-Rain"}
{0xbcaec5, "Asustek Computer"}
{0xbcb181, "Sharp"}
{0xbcb1f3, "Samsung Electronics"}
{0xbcb852, "Cybera"}
{0xbcbbc9, "Kellendonk Elektronik GmbH"}
{0xbcc168, "DInBox Sverige AB"}
{0xbcc61a, "Spectra Embedded Systems"}
{0xbcc810, "Cisco Spvtg"}
{0xbccd45, "Voismart"}
{0xbcd5b6, "d2d technologies"}
{0xbce09d, "Eoslink"}
{0xbce59f, "Waterworld Technology Co."}
{0xbcea2b, "CityCom GmbH"}
{0xbcf2af, "devolo AG"}
{0xbcfe8c, "Altronic"}
{0xbcffac, "Topcon"}
{0xc00d7e, "Additech"}
{0xc01242, "Alpha Security Products"}
{0xc0143d, "Hon Hai Precision Ind. Co."}
{0xc01885, "Hon Hai Precision Ind. Co."}
{0xc01e9b, "Pixavi AS"}
{0xc02250, "Private"}
{0xc02506, "AVM GmbH"}
{0xc027b9, "Beijing National Railway Research & Design Institute  of Signal & Communication"}
{0xc02973, "Audyssey Laboratories "}
{0xc029f3, "XySystem"}
{0xc02bfc, "iNES. applied informatics GmbH"}
{0xc02c7a, "Shen Zhen Horn audio Co."}
{0xc035bd, "Velocytech Aps"}
{0xc038f9, "Nokia Danmark A/S"}
{0xc03b8f, "Minicom Digital Signage"}
{0xc03f0e, "Netgear"}
{0xc0493d, "Maitrise Technologique"}
{0xc058a7, "Pico Systems Co."}
{0xc0626b, "Cisco Systems"}
{0xc06c0f, "Dobbs Stanford"}
{0xc07e40, "Shenzhen XDK Communication Equipment Co."}
{0xc0830a, "2Wire"}
{0xc0847a, "Apple"}
{0xc08ade, "Ruckus Wireless"}
{0xc08b6f, "S I Sistemas Inteligentes Eletronicos Ltda"}
{0xc09132, "Patriot Memory"}
{0xc09134, "ProCurve Networking by HP"}
{0xc09c92, "Coby"}
{0xc0a0de, "Multi Touch Oy"}
{0xc0a26d, "Abbott Point of Care"}
{0xc0ac54, "Sagemcom"}
{0xc0b357, "Yoshiki Electronics Industry"}
{0xc0bae6, "Application Solutions (Safety and Security)"}
{0xc0c1c0, "Cisco-Linksys"}
{0xc0c520, "Ruckus Wireless"}
{0xc0cb38, "Hon Hai Precision Ind. Co."}
{0xc0cfa3, "Creative Electronics &amp; Software"}
{0xc0d044, "Sagemcom"}
{0xc0d962, "Askey Computer"}
{0xc0df77, "Conrad Electronic SE"}
{0xc0e422, "Texas Instruments"}
{0xc0e54e, "Denx Computer Systems Gmbh"}
{0xc0eae4, "Sonicwall"}
{0xc0f8da, "Hon Hai Precision Ind. Co."}
{0xc40142, "MaxMedia Technology Limited"}
{0xc40acb, "Cisco Systems"}
{0xc40f09, "Hermes electronic GmbH"}
{0xc4108a, "Ruckus Wireless"}
{0xc416fa, "Prysm"}
{0xc417fe, "Hon Hai Precision Ind. Co."}
{0xc4198b, "Dominion Voting Systems"}
{0xc41ece, "HMI Sources"}
{0xc4237a, "WhizNets"}
{0xc4242e, "Galvanic Applied Sciences"}
{0xc42c03, "Apple"}
{0xc436da, "Rusteletech"}
{0xc43a9f, "Siconix"}
{0xc43c3c, "Cybelec SA"}
{0xc43dc7, "Netgear"}
{0xc44619, "Hon Hai Precision Ind. Co."}
{0xc44ad0, "Fireflies Rtls"}
{0xc44b44, "Omniprint"}
{0xc455a6, "Cadac Holdings"}
{0xc45600, "Galleon Embedded Computing"}
{0xc45976, "Fugoo"}
{0xc46044, "Everex Electronics Limited"}
{0xc46354, "U-Raku"}
{0xc46413, "Cisco Systems"}
{0xc467b5, "Libratone A/S"}
{0xc47130, "Fon Technology S.L."}
{0xc471fe, "Cisco Systems"}
{0xc47b2f, "Beijing JoinHope Image Technology"}
{0xc47ba3, "Navis"}
{0xc47d4f, "Cisco Systems"}
{0xc4823f, "Fujian Newland Auto-ID Tech. Co"}
{0xc48508, "Intel"}
{0xc49300, "8Devices"}
{0xc49313, "100fio networks technology"}
{0xc495a2, "Shenzhen Weijiu Industry AND Trade Development CO."}
{0xc49805, "Minieum Networks"}
{0xc4aaa1, "Summit Development, Spol.s r.o."}
{0xc4b512, "General Electric Digital Energy"}
{0xc4c19f, "National Oilwell Varco Instrumentation, Monitoring, and Optimization (NOV IMO)"}
{0xc4cad9, "Hangzhou H3C Technologies Co., Limited"}
{0xc4cd45, "Beijing Boomsense Technology CO."}
{0xc4d489, "JiangSu Joyque Information Industry Co."}
{0xc4d987, "Intel Corporate"}
{0xc4e17c, "U2S co."}
{0xc4eeae, "VSS Monitoring"}
{0xc4eef5, "Oclaro"}
{0xc4f464, "Spica international"}
{0xc4fce4, "DishTV NZ"}
{0xc802a6, "Beijing Newmine Technology"}
{0xc80718, "TDSi"}
{0xc80aa9, "Quanta Computer"}
{0xc81afe, "Dlogic Gmbh"}
{0xc81e8e, "ADV Security (S) Pte"}
{0xc8208e, "Storagedata"}
{0xc8292a, "Barun Electronics"}
{0xc82a14, "Apple"}
{0xc82e94, "Halfa Enterprise Co."}
{0xc83232, "Hunting Innova"}
{0xc8334b, "Apple"}
{0xc835b8, "Ericsson, EAB/RWI/K"}
{0xc83a35, "Tenda Technology Co."}
{0xc83b45, "JRI-Maxant"}
{0xc83e99, "Texas Instruments"}
{0xc83ea7, "Kunbus Gmbh"}
{0xc84529, "IMK Networks Co."}
{0xc84544, "Shanghai Enlogic Electric Technology Co."}
{0xc848f5, "Medison Xray Co."}
{0xc84c75, "Cisco Systems"}
{0xc85645, "Intermas France"}
{0xc86000, "Asustek Computer"}
{0xc864c7, "zte"}
{0xc86c1e, "Display Systems"}
{0xc86c87, "Zyxel Communications"}
{0xc86cb6, "Optcom Co."}
{0xc87248, "Aplicom Oy"}
{0xc87b5b, "zte"}
{0xc87cbc, "Valink Co."}
{0xc87d77, "Shenzhen Kingtech Communication Equipment Co."}
{0xc87e75, "Samsung Electronics Co."}
{0xc88439, "Sunrise Technologies"}
{0xc88447, "Beautiful Enterprise Co."}
{0xc8873b, "Net Optics"}
{0xc88b47, "Opticos s.r.l."}
{0xc8903e, "Pakton Technologies"}
{0xc89383, "Embedded Automation"}
{0xc894d2, "Jiangsu Datang  Electronic Products Co."}
{0xc8979f, "Nokia"}
{0xc89c1d, "Cisco Systems"}
{0xc89cdc, "Elitegroup Computer System CO."}
{0xc8a1b6, "Shenzhen Longway Technologies Co."}
{0xc8a1ba, "Neul"}
{0xc8a620, "Nebula"}
{0xc8a70a, "Verizon Business"}
{0xc8a729, "SYStronics Co."}
{0xc8aa21, "Motorola Mobility"}
{0xc8aacc, "Private"}
{0xc8af40, "marco Systemanalyse und Entwicklung GmbH"}
{0xc8bcc8, "Apple"}
{0xc8c126, "ZPM Industria e Comercio Ltda"}
{0xc8c13c, "RuggedTek Hangzhou Co."}
{0xc8cd72, "Sagemcom"}
{0xc8d15e, "Huawei Technologies Co."}
{0xc8d1d1, "AGAiT Technology"}
{0xc8d2c1, "Jetlun (Shenzhen)"}
{0xc8d5fe, "Shenzhen Zowee Technology Co."}
{0xc8df7c, "Nokia"}
{0xc8ee08, "Tangtop Technology Co."}
{0xc8ef2e, "Beijing Gefei Tech. Co."}
{0xc8f406, "Avaya"}
{0xc8f704, "Building Block Video"}
{0xc8f733, "Intel Corporate"}
{0xc8f981, "Seneca s.r.l."}
{0xc8f9f9, "Cisco Systems"}
{0xc8fe30, "Bejing Dayo Mobile Communication Technology"}
{0xcc0080, "Trust System Co.,"}
{0xcc051b, "Samsung Electronics Co."}
{0xcc08e0, "Apple"}
{0xcc09c8, "Imaqliq"}
{0xcc0cda, "Miljovakt AS"}
{0xcc1eff, "Metrological Group BV"}
{0xcc2218, "InnoDigital Co."}
{0xcc34d7, "Gewiss S.p.a."}
{0xcc43e3, "Trump s.a."}
{0xcc501c, "KVH Industries"}
{0xcc5076, "Ocom Communications"}
{0xcc52af, "Universal Global Scientific Industrial Co."}
{0xcc5459, "OnTime Networks AS"}
{0xcc55ad, "RIM"}
{0xcc5c75, "Weightech Com. Imp. Exp. Equip. Pesagem Ltda"}
{0xcc5d4e, "ZyXEL Communications"}
{0xcc60bb, "Empower RF Systems"}
{0xcc69b0, "Global Traffic Technologies"}
{0xcc6b98, "Minetec Wireless Technologies"}
{0xcc6bf1, "Sound Masking"}
{0xcc6da0, "Roku"}
{0xcc6def, "TJK Tietolaite Oy"}
{0xcc7669, "Seetech"}
{0xcc7a30, "Cmax Wireless Co."}
{0xcc7d37, "Motorola Mobility"}
{0xcc7ee7, "Panasonic AVC Networks Company"}
{0xcc8ce3, "Texas Instruments"}
{0xcc9093, "Hansong Tehnologies"}
{0xcc944a, "Pfeiffer Vacuum GmbH"}
{0xcc96a0, "Huawei Device Co."}
{0xcc9e00, "Nintendo Co."}
{0xcca374, "Guangdong Guanglian Electronic TechnologyLtd"}
{0xccaf78, "Hon Hai Precision Ind. Co."}
{0xccb255, "D-Link International"}
{0xccb55a, "Fraunhofer Itwm"}
{0xccb888, "AnB Securite s.a."}
{0xccb8f1, "Eagle Kingdom Technologies Limited"}
{0xccbe71, "OptiLogix BV"}
{0xccc50a, "Shenzhen Dajiahao Technology Co."}
{0xccc62b, "Tri-Systems"}
{0xccc8d7, "Cias Elettronica srl"}
{0xcccc4e, "Sun Fountainhead USA. "}
{0xcccd64, "SM-Electronic GmbH"}
{0xccce40, "Janteq"}
{0xccd811, "Aiconn Technology"}
{0xccd9e9, "SCR Engineers"}
{0xcce7df, "American Magnetics"}
{0xccea1c, "Dconworks  Co."}
{0xcceed9, "Deto Mechatronic GmbH"}
{0xccef48, "Cisco Systems"}
{0xccf3a5, "Chi Mei Communication Systems"}
{0xccf67a, "Ayecka Communication Systems"}
{0xccf841, "Lumewave"}
{0xccf8f0, "Xi'an Hisu Multimedia Technology Co."}
{0xccf954, "Avaya"}
{0xccf9e8, "Samsung Electronics Co."}
{0xccfc6d, "RIZ Transmitters"}
{0xccfcb1, "Wireless Technology"}
{0xccfe3c, "Samsung Electronics"}
{0xd00790, "Texas Instruments"}
{0xd0131e, "Sunrex Technology"}
{0xd0154a, "zte"}
{0xd0176a, "Samsung Electronics Co."}
{0xd01aa7, "UniPrint"}
{0xd01cbb, "Beijing Ctimes Digital Technology Co."}
{0xd023db, "Apple"}
{0xd02788, "Hon Hai Precision Ind.Co.Ltd"}
{0xd03110, "Ingenic Semiconductor Co."}
{0xd03761, "Texas Instruments"}
{0xd0542d, "Cambridge Industries(Group) Co."}
{0xd0574c, "Cisco Systems"}
{0xd05785, "Pantech Co."}
{0xd05875, "Active Control Technology"}
{0xd059c3, "CeraMicro Technology"}
{0xd05a0f, "I-bt Digital Co."}
{0xd05fce, "Hitachi Data Systems"}
{0xd0667b, "Samsung Electronics Co."}
{0xd067e5, "Dell"}
{0xd0699e, "Luminex Lighting Control Equipment"}
{0xd075be, "Reno A&amp;E"}
{0xd07de5, "Forward Pay Systems"}
{0xd08999, "Apcon"}
{0xd08cb5, "Texas Instruments"}
{0xd093f8, "Stonestreet One"}
{0xd09b05, "Emtronix"}
{0xd0a311, "Neuberger Gebudeautomation GmbH"}
{0xd0aeec, "Alpha Networks"}
{0xd0afb6, "Linktop Technology Co."}
{0xd0b33f, "Shenzhen Tinno Mobile Technology Co."}
{0xd0b53d, "Sepro Robotique"}
{0xd0bb80, "SHL Telemedicine International"}
{0xd0c1b1, "Samsung Electronics Co."}
{0xd0c282, "Cisco Systems"}
{0xd0cf5e, "Energy Micro AS"}
{0xd0d0fd, "Cisco Systems"}
{0xd0d286, "Beckman Coulter Biomedical K.K."}
{0xd0d3fc, "Mios"}
{0xd0df9a, "Liteon Technology"}
{0xd0dfc7, "Samsung Electronics Co."}
{0xd0e347, "Yoga"}
{0xd0e40b, "Wearable"}
{0xd0e54d, "Pace plc"}
{0xd0eb9e, "Seowoo"}
{0xd0f0db, "Ericsson"}
{0xd0f73b, "Helmut Mauell GmbH"}
{0xd4000d, "Phoenix Broadband Technologies"}
{0xd4024a, "Delphian Systems"}
{0xd411d6, "ShotSpotter"}
{0xd41296, "Anobit Technologies"}
{0xd412bb, "Quadrant Components"}
{0xd41c1c, "RCF S.p.a."}
{0xd41f0c, "TVI Vision Oy"}
{0xd4206d, "HTC"}
{0xd428b2, "ioBridge"}
{0xd42c3d, "Sky Light Digital Limited"}
{0xd43ae9, "Dongguan ipt Industrial CO."}
{0xd43d67, "Carma Industries"}
{0xd443a8, "Changzhou Haojie Electric Co."}
{0xd44b5e, "Taiyo Yuden CO."}
{0xd44c24, "Vuppalamritha Magnetic Components"}
{0xd44ca7, "Informtekhnika & Communication"}
{0xd44f80, "Kemper Digital GmbH"}
{0xd4507a, "Ceiva Logic"}
{0xd45251, "IBT Ingenieurbureau Broennimann Thun"}
{0xd45297, "nSTREAMS Technologies"}
{0xd453af, "Vigo System S.A."}
{0xd45ab2, "Galleon Systems"}
{0xd45d42, "Nokia"}
{0xd466a8, "Riedo Networks GmbH"}
{0xd46cbf, "Goodrich ISR"}
{0xd46cda, "CSM GmbH"}
{0xd46f42, "Waxess USA"}
{0xd479c3, "Cameronet GmbH &amp; Co. KG"}
{0xd47b75, "Harting Electronics Gmbh & Co. KG"}
{0xd4823e, "Argosy Technologies"}
{0xd48564, "Hewlett-Packard Company"}
{0xd487d8, "Samsung Electronics"}
{0xd48890, "Samsung Electronics Co."}
{0xd48faa, "Sogecam Industrial"}
{0xd491af, "Electroacustica General Iberica"}
{0xd4945a, "Cosmo CO."}
{0xd494a1, "Texas Instruments"}
{0xd496df, "Sungjin C&T Co."}
{0xd49a20, "Apple"}
{0xd49c28, "JayBird Gear"}
{0xd49c8e, "University of Fukui"}
{0xd49e6d, "Wuhan Zhongyuan Huadian Science & Technology Co.,"}
{0xd4a02a, "Cisco Systems"}
{0xd4a425, "Smax Technology Co."}
{0xd4a928, "GreenWave Reality"}
{0xd4aaff, "Micro World"}
{0xd4ae52, "Dell"}
{0xd4bed9, "Dell"}
{0xd4c1fc, "Nokia"}
{0xd4c766, "Acentic GmbH"}
{0xd4ca6d, "Routerboard.com"}
{0xd4cbaf, "Nokia"}
{0xd4ceb8, "Enatel"}
{0xd4d184, "ADB Broadband Italia"}
{0xd4d249, "Power Ethernet"}
{0xd4d748, "Cisco Systems"}
{0xd4d898, "Korea CNO Tech Co."}
{0xd4e32c, "S. Siedle & Sohne"}
{0xd4e33f, "Alcatel-Lucent"}
{0xd4e8b2, "Samsung Electronics"}
{0xd4ec0c, "Harley-Davidson Motor Company"}
{0xd4f027, "Navetas Energy Management"}
{0xd4f0b4, "Napco Security Technologies"}
{0xd4f143, "Iproad."}
{0xd4f63f, "IEA S.r.l."}
{0xd8052e, "Skyviia"}
{0xd80de3, "FXI Technologies AS"}
{0xd81bfe, "Twinlinx"}
{0xd81c14, "Compacta International"}
{0xd824bd, "Cisco Systems"}
{0xd826b9, "Guangdong Coagent Electronics S &T Co."}
{0xd828c9, "General Electric Consumer and Industrial"}
{0xd82986, "Best Wish Technology"}
{0xd82a7e, "Nokia"}
{0xd83062, "Apple"}
{0xd8337f, "Office FA.com Co."}
{0xd842ac, "FreeComm Data Communication Co."}
{0xd84606, "Silicon Valley Global Marketing"}
{0xd84b2a, "Cognitas Technologies"}
{0xd8543a, "Texas Instruments"}
{0xd85d4c, "Tp-link Technologies Co."}
{0xd85d84, "CAx soft GmbH"}
{0xd86bf7, "Nintendo Co."}
{0xd87157, "Lenovo Mobile Communication Technology"}
{0xd87533, "Nokia"}
{0xd8760a, "Escort"}
{0xd878e5, "Kuhn SA"}
{0xd87988, "Hon Hai Precision Ind. Co."}
{0xd8952f, "Texas Instruments"}
{0xd89685, "GoPro"}
{0xd8973b, "Emerson Network Power Embedded Power"}
{0xd89760, "C2 Development"}
{0xd89db9, "eMegatech International"}
{0xd89e3f, "Apple"}
{0xd8a25e, "Apple"}
{0xd8ae90, "Itibia Technologies"}
{0xd8b12a, "Panasonic Mobile Communications Co."}
{0xd8b377, "HTC"}
{0xd8b6c1, "NetworkAccountant"}
{0xd8b8f6, "Nantworks"}
{0xd8b90e, "Triple Domain Vision Co."}
{0xd8bf4c, "Victory Concept Electronics Limited"}
{0xd8c068, "Netgenetech.co."}
{0xd8c3fb, "Detracom"}
{0xd8c7c8, "Aruba Networks"}
{0xd8c99d, "EA Display Limited"}
{0xd8d385, "Hewlett-Packard Company"}
{0xd8d67e, "GSK CNC Equipment Co."}
{0xd8df0d, "beroNet GmbH"}
{0xd8e3ae, "Cirtec Medical Systems"}
{0xd8e72b, "OnPATH Technologies"}
{0xd8e743, "Wush"}
{0xd8e952, "Keopsys"}
{0xd8eb97, "Trendnet"}
{0xd8f0f2, "Zeebo"}
{0xd8fe8f, "IDFone Co."}
{0xdc0265, "Meditech Kft"}
{0xdc05ed, "Nabtesco "}
{0xdc07c1, "HangZhou QiYang Technology Co."}
{0xdc0b1a, "ADB Broadband SpA"}
{0xdc0ea1, "Compal Information (kunshan) CO."}
{0xdc16a2, "Medtronic Diabetes"}
{0xdc175a, "Hitachi High-Technologies"}
{0xdc1d9f, "U & B tech"}
{0xdc1ea3, "Accensus"}
{0xdc2008, "ASD Electronics "}
{0xdc2b61, "Apple"}
{0xdc2b66, "Infoblock"}
{0xdc2c26, "Iton Technology Limited"}
{0xdc2e6a, "HCT. Co."}
{0xdc309c, "SAY Systems Limited"}
{0xdc3350, "TechSAT GmbH"}
{0xdc3c2e, "Manufacturing System Insights"}
{0xdc3c84, "Ticom Geomatics"}
{0xdc3e51, "Solberg & Andersen AS"}
{0xdc49c9, "Casco Signal"}
{0xdc4ede, "Shinyei Technology CO."}
{0xdc7144, "Samsung Electro Mechanics"}
{0xdc7b94, "Cisco Systems"}
{0xdc9b1e, "Intercom"}
{0xdc9c52, "Sapphire Technology Limited."}
{0xdc9fdb, "Ubiquiti Networks"}
{0xdca6bd, "Beijing Lanbo Technology Co."}
{0xdca7d9, "Compressor Controls"}
{0xdca8cf, "New Spin Golf"}
{0xdca971, "Intel Corporate"}
{0xdcb4c4, "Microsoft XCG"}
{0xdcc101, "SOLiD Technologies"}
{0xdccba8, "Explora Technologies"}
{0xdcce41, "FE Global Hong Kong Limited"}
{0xdccf94, "Beijing Rongcheng Hutong Technology Co."}
{0xdcd0f7, "Bentek Systems"}
{0xdcd321, "Humax Co."}
{0xdcd87f, "Shenzhen JoinCyber Telecom Equipment"}
{0xdcdeca, "Akyllor"}
{0xdce2ac, "Lumens Digital Optics"}
{0xdce71c, "AUG Elektronik GmbH"}
{0xdcf05d, "Letta Teknoloji"}
{0xdcf858, "Lorent Networks"}
{0xdcfad5, "Strong Ges.m.b.h."}
{0xe005c5, "Tp-link Technologies Co."}
{0xe00b28, "Inovonics"}
{0xe00c7f, "Nintendo Co."}
{0xe0143e, "Modoosis"}
{0xe01c41, "Aerohive Networks"}
{0xe01cee, "Bravo Tech"}
{0xe01e07, "Anite Telecoms  US."}
{0xe01f0a, "Xslent Energy Technologies."}
{0xe0247f, "Huawei Technologies Co."}
{0xe02538, "Titan Pet Products"}
{0xe02630, "Intrigue Technologies"}
{0xe02636, "Nortel Networks"}
{0xe0271a, "TTC Next-generation Home Network System WG"}
{0xe02a82, "Universal Global Scientific Industrial Co."}
{0xe03005, "Alcatel-Lucent Shanghai Bell Co."}
{0xe039d7, "Plexxi"}
{0xe03c5b, "Shenzhen Jiaxinjie Electron Co."}
{0xe03e7d, "data-complex GmbH"}
{0xe0469a, "Netgear"}
{0xe0589e, "Laerdal Medical"}
{0xe05b70, "Innovid, Co."}
{0xe05da6, "Detlef Fink Elektronik &amp; Softwareentwicklung"}
{0xe05fb9, "Cisco Systems"}
{0xe061b2, "Hangzhou Zenointel Technology CO."}
{0xe06290, "Jinan Jovision Science & Technology Co."}
{0xe064bb, "DigiView S.r.l."}
{0xe06995, "Pegatron"}
{0xe087b1, "Nata-Info"}
{0xe08a7e, "Exponent"}
{0xe08fec, "Repotec CO."}
{0xe09153, "XAVi Technologies"}
{0xe091f5, "Netgear"}
{0xe09467, "Intel Corporate"}
{0xe09579, "Orthosoft, D/b/a Zimmer CAS"}
{0xe0a1d7, "SFR"}
{0xe0a670, "Nokia"}
{0xe0abfe, "Orb Networks"}
{0xe0ae5e, "Alps Electric Co"}
{0xe0b9a5, "Azurewave"}
{0xe0b9ba, "Apple"}
{0xe0bc43, "C2 Microsystems"}
{0xe0c286, "Aisai Communication Technology Co."}
{0xe0c922, "Jireh Energy Tech."}
{0xe0ca4d, "Shenzhen Unistar Communication Co."}
{0xe0ca94, "Askey Computer"}
{0xe0cb1d, "Private"}
{0xe0cb4e, "Asustek Computer"}
{0xe0cf2d, "Gemintek"}
{0xe0d10a, "Katoudenkikougyousyo co"}
{0xe0d7ba, "Texas Instruments"}
{0xe0dadc, "JVC Kenwood"}
{0xe0e751, "Nintendo Co."}
{0xe0e8e8, "Olive Telecommunication Pvt."}
{0xe0ed1a, "vastriver Technology Co."}
{0xe0ee1b, "Panasonic Automotive Systems Company of America"}
{0xe0ef25, "Lintes Technology Co."}
{0xe0f211, "Digitalwatt"}
{0xe0f379, "Vaddio"}
{0xe0f847, "Apple"}
{0xe0f9be, "Cloudena"}
{0xe4115b, "Hewlett Packard"}
{0xe41289, "topsystem Systemhaus GmbH"}
{0xe41c4b, "V2 Technology"}
{0xe41f13, "IBM"}
{0xe425e9, "Color-Chip"}
{0xe42771, "Smartlabs"}
{0xe42ad3, "Magneti Marelli S.p.A. Powertrain"}
{0xe42c56, "Lilee Systems"}
{0xe42ff6, "Unicore communication"}
{0xe43593, "Hangzhou GoTo technologyLtd"}
{0xe435fb, "Sabre Technology (Hull)"}
{0xe437d7, "Henri Depaepes."}
{0xe441e6, "Ottec Technology GmbH"}
{0xe446bd, "C&C Technic Taiwan CO."}
{0xe448c7, "Cisco Spvtg"}
{0xe44e18, "Gardasoft VisionLimited"}
{0xe44f29, "MA Lighting Technology GmbH"}
{0xe455ea, "Dedicated Computing"}
{0xe46449, "Motorola Mobility"}
{0xe467ba, "Danish Interpretation Systems A/S"}
{0xe46c21, "messMa GmbH"}
{0xe4751e, "Getinge Sterilization AB"}
{0xe477d4, "Minrray Industry Co."}
{0xe47cf9, "Samsung Electronics Co."}
{0xe48399, "Motorola Mobility"}
{0xe48ad5, "RF Window CO."}
{0xe497f0, "Shanghai VLC Technologies Co."}
{0xe4a5ef, "Tron Link Electronics CO."}
{0xe4ab46, "UAB Selteka"}
{0xe4ad7d, "SCL Elements"}
{0xe4afa1, "Hes-so"}
{0xe4b021, "Samsung Electronics Co."}
{0xe4c6e6, "Mophie"}
{0xe4c806, "Ceiec Electric Technology"}
{0xe4ce8f, "Apple"}
{0xe4d53d, "Hon Hai Precision Ind. Co."}
{0xe4d71d, "Oraya Therapeutics"}
{0xe4dd79, "En-Vision America"}
{0xe4e0c5, "Samsung Electronics Co."}
{0xe4ec10, "Nokia"}
{0xe4fa1d, "PAD Peripheral Advanced Design"}
{0xe4ffdd, "Electron India"}
{0xe8039a, "Samsung Electronics Co."}
{0xe8040b, "Apple"}
{0xe80462, "Cisco Systems"}
{0xe8056d, "Nortel Networks"}
{0xe80688, "Apple"}
{0xe80b13, "Akib Systems Taiwan"}
{0xe80c38, "Daeyoung Information System CO."}
{0xe80c75, "Syncbak"}
{0xe81132, "Samsung Electronics Co."}
{0xe81324, "GuangZhou Bonsoninfo System CO."}
{0xe82877, "TMY Co."}
{0xe828d5, "Cots Technology"}
{0xe83935, "Hewlett Packard"}
{0xe839df, "Askey Computer"}
{0xe83a97, "OCZ Technology Group"}
{0xe83eb6, "RIM"}
{0xe83efb, "Geodesic"}
{0xe84040, "Cisco Systems"}
{0xe840f2, "Pegatron"}
{0xe843b6, "Qnap Systems"}
{0xe84e06, "Edup International (hk) CO."}
{0xe84ece, "Nintendo Co."}
{0xe85b5b, "LG Electronics"}
{0xe85e53, "Infratec Datentechnik GmbH"}
{0xe86cda, "Supercomputers and Neurocomputers Research Center"}
{0xe86d52, "Motorola Mobility"}
{0xe86d6e, "Control & Display Systems t/a Cdsrail"}
{0xe8757f, "Firs Technologies(shenzhen) Co."}
{0xe878a1, "Beoview Intercom DOO"}
{0xe87af3, "S5 Tech S.r.l."}
{0xe88df5, "Znyx Networks"}
{0xe8944c, "Cogent Healthcare Systems"}
{0xe8995a, "PiiGAB, Processinformation i Goteborg AB"}
{0xe89a8f, "Quanta Computer"}
{0xe89d87, "Toshiba"}
{0xe8a4c1, "Deep Sea Electronics PLC"}
{0xe8b4ae, "Shenzhen C&D Electronics Co."}
{0xe8b748, "Cisco Systems"}
{0xe8ba70, "Cisco Systems"}
{0xe8be81, "Sagemcom"}
{0xe8c229, "H-Displays (MSC) Bhd"}
{0xe8c320, "Austco Communication Systems"}
{0xe8cc32, "Micronet "}
{0xe8da96, "Zhuhai Tianrui Electrical Power Tech. Co."}
{0xe8daaa, "VideoHome Technology"}
{0xe8dff2, "PRF Co."}
{0xe8e08f, "Gravotech Marking SAS"}
{0xe8e0b7, "Toshiba"}
{0xe8e1e2, "Energotest"}
{0xe8e5d6, "Samsung Electronics Co."}
{0xe8e732, "Alcatel-Lucent"}
{0xe8e776, "Shenzhen Kootion Technology Co."}
{0xe8f1b0, "Sagemcom SAS"}
{0xe8f928, "Rftech SRL"}
{0xec1120, "FloDesign Wind Turbine"}
{0xec14f6, "BioControl AS"}
{0xec2368, "IntelliVoice Co."}
{0xec3091, "Cisco Systems"}
{0xec3bf0, "NovelSat"}
{0xec3f05, "Institute 706, The Second Academy China Aerospace Science & Industry"}
{0xec43e6, "Awcer"}
{0xec4476, "Cisco Systems"}
{0xec4644, "TTK SAS"}
{0xec4670, "Meinberg Funkuhren GmbH &amp; Co. KG"}
{0xec542e, "Shanghai XiMei Electronic Technology Co."}
{0xec55f9, "Hon Hai Precision Ind. Co."}
{0xec5c69, "Mitsubishi Heavy Industries Mechatronics Systems"}
{0xec6264, "Global411 Internet Services"}
{0xec63e5, "ePBoard Design"}
{0xec66d1, "B&amp;W Group"}
{0xec6c9f, "Chengdu Volans Technology CO."}
{0xec7c74, "Justone Technologies Co."}
{0xec7d9d, "MEI"}
{0xec836c, "RM Tech Co."}
{0xec852f, "Apple"}
{0xec8ead, "DLX"}
{0xec9233, "Eddyfi NDT"}
{0xec9681, "2276427 Ontario"}
{0xec986c, "Lufft Mess- und Regeltechnik GmbH"}
{0xec98c1, "Beijing Risbo Network Technology Co."}
{0xec9a74, "Hewlett Packard"}
{0xec9b5b, "Nokia"}
{0xec9ecd, "Emerson Network Power and Embedded Computing"}
{0xeca86b, "Elitegroup Computer Systems CO."}
{0xecb106, "Acuro Networks"}
{0xecbbae, "Digivoice Tecnologia em Eletronica Ltda"}
{0xecbd09, "Fusion Electronics"}
{0xecc38a, "Accuenergy (canada)"}
{0xecc882, "Cisco Systems"}
{0xeccd6d, "Allied Telesis"}
{0xecd00e, "MiraeRecognition Co."}
{0xecde3d, "Lamprey Networks"}
{0xece09b, "Samsung electronics CO."}
{0xece555, "Hirschmann Automation"}
{0xece744, "Omntec mfg."}
{0xece90b, "Sistema Solucoes Eletronicas Ltda - Easytech"}
{0xece9f8, "Guang Zhou TRI-SUN Electronics Technology  Co."}
{0xecea03, "Darfon Lighting"}
{0xecf00e, "Abocom"}
{0xecf236, "Neomontana Electronics"}
{0xecfaaa, "The IMS Company"}
{0xecfe7e, "BlueRadios"}
{0xf0007f, "Janz - Contadores de Energia"}
{0xf0022b, "Chrontel"}
{0xf00248, "SmarteBuilding"}
{0xf00786, "Shandong Bittel Electronics Co."}
{0xf008f1, "Samsung Electronics Co."}
{0xf013c3, "Shenzhen Fenda Technology CO."}
{0xf01c13, "LG Electronics"}
{0xf02408, "Talaris (Sweden) AB"}
{0xf02572, "Cisco Systems"}
{0xf0264c, "Dr. Sigrist AG"}
{0xf02a61, "Waldo Networks"}
{0xf02fd8, "Bi2-Vision"}
{0xf03a55, "Omega Elektronik AS"}
{0xf04335, "DVN(Shanghai)Ltd."}
{0xf04a2b, "Pyramid Computer Gmbh"}
{0xf04b6a, "Scientific Production Association Siberian Arsenal"}
{0xf04bf2, "Jtech Communications"}
{0xf04da2, "Dell"}
{0xf05849, "CareView Communications"}
{0xf05d89, "Dycon Limited"}
{0xf0620d, "Shenzhen Egreat Tech"}
{0xf06281, "ProCurve Networking by HP"}
{0xf065dd, "Primax Electronics"}
{0xf06853, "Integrated"}
{0xf077d0, "Xcellen"}
{0xf07bcb, "Hon Hai Precision Ind. Co."}
{0xf07d68, "D-Link"}
{0xf081af, "IRZ Automation Technologies"}
{0xf08bfe, "Costel."}
{0xf0933a, "NxtConect"}
{0xf09cbb, "RaonThink"}
{0xf0a225, "Private"}
{0xf0a764, "GST Co."}
{0xf0ad4e, "Globalscale Technologies"}
{0xf0ae51, "Xi3"}
{0xf0b479, "Apple"}
{0xf0b6eb, "Poslab Technology Co."}
{0xf0bcc8, "MaxID (Pty)"}
{0xf0bdf1, "Sipod"}
{0xf0bf97, "Sony"}
{0xf0c24c, "Zhejiang FeiYue Digital Technology Co."}
{0xf0c27c, "Mianyang Netop Telecom Equipment Co."}
{0xf0c88c, "LeddarTech"}
{0xf0cba1, "Apple"}
{0xf0d14f, "Linear"}
{0xf0d767, "Axema Passagekontroll AB"}
{0xf0da7c, "RLH Industries"}
{0xf0db30, "Yottabyte"}
{0xf0de71, "Shanghai EDO Technologies Co."}
{0xf0deb9, "ShangHai Y&Y Electronics Co."}
{0xf0def1, "Wistron InfoComm (Kunshan)Co"}
{0xf0e5c3, "Draegerwerk AG &amp;amp; Co. KG aA"}
{0xf0e77e, "Samsung Electronics Co."}
{0xf0ec39, "Essec"}
{0xf0ed1e, "Bilkon Bilgisayar Kontrollu Cih. Im.Ltd."}
{0xf0eebb, "Vipar Gmbh"}
{0xf0f002, "Hon Hai Precision Ind. Co."}
{0xf0f755, "Cisco Systems"}
{0xf0f7b3, "Phorm"}
{0xf0f842, "Keebox"}
{0xf0f9f7, "IES GmbH &amp; Co. KG"}
{0xf0fb56, "Apple"}
{0xf40321, "BeNeXt B.V."}
{0xf4044c, "ValenceTech Limited"}
{0xf40b93, "Research In Motion"}
{0xf41f0b, "Yamabishi"}
{0xf436e1, "Abilis Systems Sarl"}
{0xf43814, "Shanghai Howell Electronic Co."}
{0xf43d80, "FAG Industrial Services GmbH"}
{0xf43e61, "Shenzhen Gongjin Electronics Co."}
{0xf43e9d, "Benu Networks"}
{0xf44227, "S & S Research"}
{0xf44450, "BND Co."}
{0xf445ed, "Portable Innovation Technology"}
{0xf44848, "Amscreen Group"}
{0xf44efd, "Actions Semiconductor Co.,Ltd.(Cayman Islands)"}
{0xf450eb, "Telechips"}
{0xf45595, "Hengbao"}
{0xf4559c, "Huawei Technologies Co."}
{0xf455e0, "Niceway CNC Technology Co.,Ltd.Hunan Province"}
{0xf45fd4, "Cisco Spvtg"}
{0xf45ff7, "DQ Technology"}
{0xf46349, "Diffon"}
{0xf46d04, "Asustek Computer"}
{0xf473ca, "Conversion Sound"}
{0xf47626, "Viltechmeda UAB "}
{0xf47acc, "SolidFire"}
{0xf47f35, "Cisco Systems"}
{0xf48771, "Infoblox"}
{0xf48e09, "Nokia"}
{0xf49461, "NexGen Storage"}
{0xf49f54, "Samsung Electronics"}
{0xf4a52a, "Hawa Technologies"}
{0xf4acc1, "Cisco Systems"}
{0xf4b164, "Lightning Telecommunications Technology Co."}
{0xf4b549, "Yeastar Technology Co."}
{0xf4c714, "Huawei Device Co."}
{0xf4c795, "WEY Elektronik AG"}
{0xf4cae5, "Freebox SA"}
{0xf4ce46, "Hewlett-Packard Company"}
{0xf4d9fb, "Samsung Electronics CO."}
{0xf4dc4d, "Beijing CCD Digital Technology Co."}
{0xf4dcda, "Zhuhai Jiahe Communication Technology Co., limited"}
{0xf4e142, "Delta Elektronika BV"}
{0xf4e6d7, "Solar Power Technologies"}
{0xf4ea67, "Cisco Systems"}
{0xf4ec38, "Tp-link Technologies CO."}
{0xf4fc32, "Texas Instruments"}
{0xf80332, "Khomp"}
{0xf80cf3, "LG Electronics"}
{0xf80f41, "Wistron InfoComm(ZhongShan)"}
{0xf80f84, "Natural Security SAS"}
{0xf81037, "Atopia Systems"}
{0xf81d93, "Longdhua(Beijing) Controls Technology Co."}
{0xf81edf, "Apple"}
{0xf82f5b, "eGauge Systems"}
{0xf83094, "Alcatel-Lucent Telecom Limited"}
{0xf8313e, "endeavour GmbH"}
{0xf83376, "Good Mind Innovation Co."}
{0xf83553, "Magenta Research"}
{0xf83dff, "Huawei Technologies Co."}
{0xf8462d, "Syntec Incorporation"}
{0xf8472d, "X2gen Digital"}
{0xf85063, "Verathon"}
{0xf852df, "VNL Europe AB"}
{0xf866f2, "Cisco Systems"}
{0xf86971, "Seibu Electric Co.,"}
{0xf86ecf, "Arcx"}
{0xf871fe, "The Goldman Sachs Group"}
{0xf8769b, "Neopis Co."}
{0xf87b7a, "Motorola Mobility"}
{0xf87b8c, "Amped Wireless"}
{0xf8811a, "Overkiz"}
{0xf88c1c, "Kaishun Electronic Technology CO., Beijing"}
{0xf88def, "Tenebraex"}
{0xf88fca, "Google Fiber"}
{0xf8912a, "GLP German Light Products GmbH"}
{0xf893f3, "Volans"}
{0xf897cf, "Daeshin-information Technology CO."}
{0xf89955, "Fortress Technology"}
{0xf89d0d, "Control Technology"}
{0xf8a9de, "Puissance Plus"}
{0xf8ac6d, "Deltenna"}
{0xf8b599, "Guangzhou Chnavs Digital Technology Co."}
{0xf8c001, "Juniper Networks"}
{0xf8c091, "Highgates Technology"}
{0xf8c678, "Carefusion"}
{0xf8d0bd, "Samsung Electronics Co."}
{0xf8d111, "Tp-link Technologies CO."}
{0xf8d3a9, "Axan Networks"}
{0xf8d462, "Pumatronix Equipamentos Eletronicos Ltda."}
{0xf8d756, "Simm Tronic Limited "}
{0xf8dae2, "Beta LaserMike"}
{0xf8daf4, "Taishan Online Technology Co."}
{0xf8db4c, "PNY Technologies"}
{0xf8db7f, "HTC"}
{0xf8dc7a, "Variscite"}
{0xf8e7b5, "Utech Engenharia e Automaao Ltda"}
{0xf8e968, "Egker Kft."}
{0xf8ea0a, "Dipl.-Math. Michael Rauch"}
{0xf8f014, "RackWare"}
{0xf8f25a, "G-Lab GmbH"}
{0xf8f7d3, "International Communications"}
{0xf8f7ff, "Syn-tech Systems"}
{0xf8fb2f, "Santur"}
{0xf8fe5c, "Reciprocal Labs"}
{0xfc0012, "Toshiba Samsung Storage Technolgoy Korea "}
{0xfc01cd, "Fundacion Tekniker"}
{0xfc0877, "Prentke Romich Company"}
{0xfc0a81, "Motorola Solutions"}
{0xfc0fe6, "Sony Computer Entertainment "}
{0xfc10bd, "Control Sistematizado S.A."}
{0xfc1794, "InterCreative Co."}
{0xfc1fc0, "Eurecam"}
{0xfc253f, "Apple"}
{0xfc2e2d, "Lorom IndustrialLTD."}
{0xfc2f40, "Calxeda"}
{0xfc3598, "Favite"}
{0xfc4463, "Universal Audio"}
{0xfc455f, "Jiangxi Shanshui Optoelectronic Technology Co."}
{0xfc48ef, "Huawei Technologies Co."}
{0xfc4dd4, "Universal Global Scientific Industrial Co."}
{0xfc5b24, "Weibel Scientific A/S"}
{0xfc5b26, "MikroBits"}
{0xfc6198, "NEC Personal Products"}
{0xfc683e, "Directed Perception"}
{0xfc6c31, "LXinstruments GmbH"}
{0xfc7516, "D-Link International"}
{0xfc75e6, "Handreamnet"}
{0xfc7ce7, "FCI USA"}
{0xfc8329, "Trei technics"}
{0xfc8e7e, "Pace plc"}
{0xfc8fc4, "Intelligent Technology"}
{0xfc946c, "Ubivelox"}
{0xfca13e, "Samsung Electronics"}
{0xfca841, "Avaya"}
{0xfcaf6a, "Conemtech AB"}
{0xfcc23d, "Atmel"}
{0xfcc734, "Samsung Electronics Co."}
{0xfcc897, "ZTE"}
{0xfccce4, "Ascon"}
{0xfccf62, "IBM"}
{0xfcd4f2, "The Coca Cola Company"}
{0xfcd4f6, "Messana Air.Ray Conditioning s.r.l."}
{0xfce192, "Sichuan Jinwangtong Electronic Science&Technology Co"}
{0xfce23f, "Clay Paky SPA"}
{0xfce557, "Nokia"}
{0xfce892, "Hangzhou Lancable Technology Co."}
{0xfcedb9, "Arrayent"}
{0xfcf1cd, "Optex-fa Co."}
{0xfcf8ae, "Intel Corporate"}
{0xfcfaf7, "Shanghai Baud Data Communication Co."}
{0xfcfbfb, "Cisco Systems"}
{0x525400, "QEMU Virtual NIC"}
{0xb0c420, "Bochs Virtual NIC"}
{0xdeadca, "PearPC Virtual NIC"}
{0x00ffd1, "Cooperative Linux virtual NIC"},
{0, NULL}
};

static int
ethernetcode_index(struct ethertree *etherroot, struct ethernetcode *code)
{
	struct etherindex tmp, *entry;
	char line[1024], *p, *e;

	strlcpy(line, code->vendor, sizeof(line));
	e = line;

	/* Walk through every single word and index it */
	while ((p = strsep(&e, " ")) != NULL) {
		tmp.index_word = p;
		if ((entry = SPLAY_FIND(ethertree, etherroot, &tmp)) == NULL) {
			/* Generate a new entry for this word */
			entry = calloc(1, sizeof(struct etherindex));
			if (entry == NULL)
				err(1, "%s: calloc", __func__);

			if ((entry->index_word = strdup(p)) == NULL)
				err(1, "%s: strdup", __func__);

			entry->list_mem = 32;
			if ((entry->list = calloc(entry->list_mem,
				 sizeof(struct ethernetcode *))) == NULL)
				err(1, "%s: calloc");

			SPLAY_INSERT(ethertree, etherroot, entry);
		}

		if (entry->list_size >= entry->list_mem) {
			struct ethernetcode **tmp;

			/* We require more memory for this key word */
			entry->list_mem <<= 1;
			tmp = realloc(entry->list,
			    entry->list_mem * sizeof(struct ethernetcode *));
			if (tmp == NULL)
				err(1, "%s: realloc", __func__);
			entry->list = tmp;
		}

		entry->list[entry->list_size++] = code;
	}

	return (0);
}

void
ethernetcode_init(void)
{
	struct ethernetcode *code = &codes[0];

	SPLAY_INIT(&etherroot);

	while (code->vendor != NULL) {
		ethernetcode_index(&etherroot, code);

		++code;
	}
}

/*
 * Returns the code that matches the best, 0 on error.
 */

static uint32_t
ethernetcode_find_best(struct etherindex **results, int size, int random)
{
	extern rand_t *honeyd_rand;
	int i, j, max = 0, count = 0;
	struct ethernetcode *code = NULL;

	if (!size)
		return (0);

	/* Reset the counters */
	for (i = 0; i < size; i++) {
		struct etherindex *ei = results[i];
		for (j = 0; j < ei->list_size; j++)
			ei->list[j]->count = 0;
	}

	for (i = 0; i < size; i++) {
		struct etherindex *ei = results[i];
		for (j = 0; j < ei->list_size; j++) {
			ei->list[j]->count++;
			if (ei->list[j]->count > max) {
				max = ei->list[j]->count;
				code = ei->list[j];
				count = 1;
			} else if (ei->list[j]->count == max && random) {
				/* Randomly select one of the best matches */
				count++;
				if (rand_uint8(honeyd_rand) % count == 0)
					code = ei->list[j];
			}
		}
	}

	return (code->prefix);
}

uint32_t
ethernetcode_find_prefix(char *vendor, int random) {
	struct etherindex *results[20];
	struct etherindex tmp, *entry;
	char line[1024], *p, *e;
	int pos = 0;

	strlcpy(line, vendor, sizeof(line));
	e = line;

	/* Walk through every single word and find the codes for it */
	while ((p = strsep(&e, " ")) != NULL && pos < 20) {
		int i;
		
		/* Change the string to lower case for the match */
		for (i = 0; i < strlen(p); i++)
			p[i] = tolower(p[i]);

		tmp.index_word = p;
		if ((entry = SPLAY_FIND(ethertree, &etherroot, &tmp)) == NULL)
			continue;

		results[pos++] = entry;
	}

	return (ethernetcode_find_best(results, pos, random));
}

struct addr *
ethernetcode_make_address(char *vendor)
{
	extern rand_t *honeyd_rand;
	uint32_t prefix = 0;
	u_char address[ETH_ADDR_LEN], *p;
	struct addr *ea;
	int i;

	/* Check if it is a regular mac address: xx:xx:xx:xx:xx:xx */
	p = address;
	for (i = 0; i < strlen(vendor) && p < address + ETH_ADDR_LEN; i += 3) {
		char hex[3];

		if (!isxdigit(vendor[i]) || !isxdigit(vendor[i+1]))
			break;

		hex[0] = vendor[i];
		hex[1] = vendor[i+1];
		hex[2] = '\0';

		*p++ = strtoul(hex, NULL, 16);

		if (i + 2 < strlen(vendor) && vendor[i + 2] != ':')
			break;
	}

	/* We could not parse the hex digits, so search for a vendor instead */
	if (p < address + ETH_ADDR_LEN) {
		if ((prefix = ethernetcode_find_prefix(vendor, 1)) == 0)
			return (NULL);

		/* We have a 24-bit prefix that is vendor dependant */
		address[2] = prefix & 0xff; prefix >>= 8;
		address[1] = prefix & 0xff; prefix >>= 8;
		address[0] = prefix & 0xff; prefix >>= 8;

		if (prefix != 0)
			return (NULL);

		for (i = 3; i < ETH_ADDR_LEN; i++)
			address[i] = rand_uint8(honeyd_rand);
	}

	if ((ea = calloc(1, sizeof(struct addr))) == NULL)
		return (NULL);

	addr_pack(ea, ADDR_TYPE_ETH, ETH_ADDR_BITS, address, ETH_ADDR_LEN);

	return (ea);
}

struct addr *
ethernetcode_clone(struct addr *src)
{
	extern rand_t *honeyd_rand;
	struct addr *ea;
	int i;

	if ((ea = calloc(1, sizeof(struct addr))) == NULL)
		return (NULL);

	memcpy(ea, src, sizeof(struct addr));

	/* Very low-level hack, might break when dnet changes */
	for (i = 3; i < ETH_ADDR_LEN; i++)
		ea->addr_data8[i] = rand_uint8(honeyd_rand);

	return (ea);
}

#define TEST(x, y) do { \
	if (ethernetcode_find_prefix(x, 0) != (y)) \
		errx(1, "%s: %s does not match %.6x", __func__, x, y); \
} while (0)

void
ethernetcode_test(void)
{
	TEST("cisco", 0x00000c);
	TEST("cisco catalyst", 0x001007);
	TEST("juniper networks", 0x000585);
	TEST("3com", 0x00103);
	TEST("zzzzzzzz xxxxxxxx", 0x000000);

	fprintf(stderr, "\t%s: OK\n", __func__);
}

void
ethernet_test(void)
{
	ethernetcode_init();

	ethernetcode_test();
}
