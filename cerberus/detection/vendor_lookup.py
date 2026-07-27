"""
Maps a MAC address to a manufacturer name using the OUI (the first 3
bytes) against data/oui.txt, a local vendor database bundled with the
project — no network call, ever. Unknown OUIs just return None.

is_likely_hypervisor() is a separate, purely cosmetic check: it flags
vendor strings that belong to VMware/VirtualBox/Hyper-V/QEMU/etc so the
CLI and alert_manager can label a device "possible VM on this machine"
instead of it looking like a mystery intruder. It doesn't change any
trust decision — a bridged VM is still a real device and still shows
up in scans like anything else.

Update the bundled OUI file with: python -m cerberus.detection.vendor_lookup --update
"""

import logging
import os
import re
from typing import Dict, Optional

logger = logging.getLogger("cerberus.detection.vendor_lookup")

# Default location of the OUI database file relative to project root
_DEFAULT_OUI_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)
    ))),
    "data", "oui.txt"
)

# Vendor name substrings (lowercased) belonging to known virtualization
# platforms. Checked as substring match, not exact match, since OUI
# databases phrase vendor names inconsistently (e.g. "VMware, Inc."
# vs "VMware" vs "Vmware Inc").
_HYPERVISOR_VENDOR_MARKERS = (
    "vmware",
    "virtualbox",
    "innotek",          # VirtualBox's original OUI registrant name
    "hyper-v",
    "microsoft hyper-v",
    "qemu",
    "xen",
    "parallels",
)

# Bundled minimal OUI dataset — covers most common home/office vendors.
# This is written to data/oui.txt if the file doesn't exist.
# Source: IEEE public OUI registry (https://regauth.standards.ieee.org)
_BUNDLED_OUI = """000000\tXerox Corporation
000001\tXerox Corporation
000002\tXerox Corporation
00000C\tCisco Systems
00000E\tFujitsu
00000F\tNext
000010\tSytek
000020\tDEC
00002A\tTRW
000037\tNorthrop Grumman
00003B\tSystec
000044\tCascade Communications
000046\tUniversity of Toronto
000049\tApricot Computers
000050\tRadisys Corporation
000052\tOncor Communications
000055\tAT&T
000058\tRaytheon Company
00005A\tS & Koch
00005E\tIANA (Multicast/Reserved)
00005F\tComputerm Corporation
000062\tBull HN Information Systems
000065\tNetwork General
000069\tSilicon Graphics
00006B\tSilicon Graphics
00006D\tCase Technology
00006E\tArtisoft
000075\tNEC Corporation
000077\tInterphase Corporation
00007A\tArdis Technologies
00007B\tResearch Machines
00007D\tZenith Electronics
00007F\tSilicon Graphics
000080\tCray Communications
000081\tSyntellect
000084\tExabyte Corporation
000086\tSaturn Systems
000089\tCayman Systems
00008A\tDatahouse Information Systems
00008E\tDovercom Corporation
000093\tProteon
000094\tAsante Technologies
000095\tDEC
000097\tLeland Stanford University
000098\tCross Com
00009F\tQuadrant Systems
0000A0\tOlympus Corporation
0000A2\tWellfleet Communications
0000A3\tNetwork Application Technology
0000A4\tFarallon Computing
0000A5\tSynoptics Communications
0000A6\tNetwork General
0000A7\tNCD Information Systems
0000A8\tStratus Computer
0000A9\tNetwork Systems Corporation
0000AA\tXerox Corporation
0000AC\tConware Computer Consulting
0000AE\tDalton Computer Corporation
0000AF\tnuclear Data
0000B0\tRaytheon Company
0000B3\tCNET Technologies
0000B4\tAmitech
0000B5\tDATA POINT CORPORATION
0000B7\tDevex
0000BB\tTri-Data Systems
0000BC\tAllen-Bradley
0000C0\tWestern Digital Corporation
0000C5\tFarallon Computing
0000C6\tHP Intelligent Networks
0000C8\tAltos Computer Systems
0000C9\tEmulex Corporation
0000CA\tLANnet Data Communications
0000CC\tSilcom Manufacturing Technology
0000D0\tUniversal Data Systems
0000D1\tAdaptec
0000D4\tPur Data
0000D7\tRolta India Limited
0000D8\tNovell / NetWorth
0000DD\tTCL/Zenith Data Systems
0000DE\tZarlink Semiconductor
0000E2\tAmdahl Corporation
0000E3\tIntegrated Micro Solutions
0000E4\tIn Focus Systems
0000E6\tApricot Computers
0000E8\tAccton Technology Corporation
0000E9\tIsolan
0000EE\tNetrix
0000EF\tAlantec
0000F0\tSamsung Electronics
0000F3\tGandalph Technologies
0000F4\tAllied Telesis
0000F6\tAMD
0000F8\tDEC
0000FB\tRecognition Equipment
0000FD\tHigher Layer Software
00017C\tSmartlink Network Systems
001177\tSmartlink Network Systems Limited
00177C\tSmartlink Network Systems Limited
A4C138\tApple, Inc.
000201\tXerox Corporation
00022D\tAgere Systems
000272\tCisco Systems
0002A5\tHewlett Packard
0002B3\tIntel Corporation
000347\tCisco Systems
000393\tApple Computer
0003E3\tCisco Systems
000412\tCisco Systems
000476\tCisco Systems
000502\tApple Computer
000508\tApple Computer
00050C\tD-Link Corporation
00053D\tCisco Systems
000546\tCisco Systems
000565\tCisco Systems
00056A\tCisco Systems
00057D\tCisco Systems
000583\tApple Computer
0005A4\tCisco Systems
0005DC\tLinksys
0005E1\tSilicon Integrated Systems
0006D6\tMitsubishi Electric
0006E6\tYamaha Corporation
0007E9\tIntel Corporation
0007F0\tNEC Computer
000846\tResearch In Motion
000874\tHP
0008A2\tADC Telecommunications
0008A3\tHewlett Packard
0008C7\tSONY Corporation
000976\tCisco Systems
0009B7\tSONY Corporation
000BDB\tApple Computer
000C41\tCisco Systems
000CDB\tNEC Computer
000D93\tApple Computer
000E08\tCisco Systems
000E35\tCisco Systems
000E38\tCisco Systems
000E84\tCisco Systems
000EC6\tCisco Systems
001005\tCisco Systems
001010\tCisco Systems
001124\tCisco Systems
00112F\tCisco Systems
001176\tCisco Systems
0011BB\tCisco Systems
0011BC\tCisco Systems
001201\tCisco Systems
001217\tCisco Systems
001229\tCisco Systems
00122D\tCisco Systems
001265\tCisco Systems
00126F\tCisco Systems
001274\tCisco Systems
001285\tHP
0012A9\tCisco Systems
0012DA\tCisco Systems
0013C3\tCisco Systems
0013C4\tCisco Systems
0013E8\tCisco Systems
001493\tApple Computer
0014A9\tCisco Systems
001560\tCisco Systems
00156D\tCisco Systems
00157F\tCisco Systems
001648\tCisco Systems
00166F\tCisco Systems
001705\tCisco Systems
001763\tCisco Systems
0017CB\tCisco Systems
001801\tCisco Systems
001825\tCisco Systems
001905\tCisco Systems
00192F\tCisco Systems
001966\tCisco Systems
001A2F\tCisco Systems
001A30\tCisco Systems
001A6C\tCisco Systems
001AA2\tCisco Systems
001AE2\tCisco Systems
001B0C\tCisco Systems
001B67\tCisco Systems
001B8F\tApple
001BC0\tCisco Systems
001C0E\tCisco Systems
001C10\tCisco Systems
001C58\tCisco Systems
001CDF\tCisco Systems
001D45\tCisco Systems
001D71\tApple
001DA2\tCisco Systems
001E13\tCisco Systems
001E14\tCisco Systems
001E49\tCisco Systems
001E4A\tCisco Systems
001E7A\tCisco Systems
001EBD\tCisco Systems
001F27\tApple
001F6C\tCisco Systems
001F6D\tCisco Systems
001FA7\tCisco Systems
002008\tCisco Systems
00201A\tCisco Systems
00201B\tCisco Systems
002021\tCisco Systems
00203A\tCisco Systems
00204C\tHP
002063\tCisco Systems
00206B\tCisco Systems
002083\tTandberg Data
002090\tCisco Systems
0020A6\tProxim
0020AF\tIntel Corporation
0020C5\tMAXTOR CORP.
0020D2\tRaytheon Company
0020D8\tNetrix
0020EO\tCisco Systems
0020F8\tCisco Systems
00212A\tCisco Systems
002155\tCisco Systems
00215A\tCisco Systems
00215C\tCisco Systems
002161\tCisco Systems
00216C\tCisco Systems
00219B\tCisco Systems
0021A0\tCisco Systems
0021D7\tCisco Systems
002219\tCisco Systems
002248\tCisco Systems
002264\tCisco Systems
0022BE\tCisco Systems
0022BD\tCisco Systems
0022D4\tCisco Systems
0022FD\tCisco Systems
002340\tCisco Systems
002413\tCisco Systems
00248C\tApple
0024D7\tCisco Systems
0025B3\tCisco Systems
0025B5\tCisco Systems
0026B9\tCisco Systems
0026CB\tCisco Systems
00270E\tCisco Systems
002716\tCisco Systems
00278D\tApple
0029C2\tCisco Systems
002A10\tCisco Systems
002C0D\tCisco Systems
00306E\tCisco Systems
003065\tCisco Systems
003089\tCisco Systems
0030F2\tCisco Systems
004005\tHP
00402B\tADC Telecommunications
00403F\tDigital Link
004048\tSemaphore Communications
00404C\tGroup Technologies
00405D\tTelcom Semiconductor
004063\tAmplinet
004065\tOptec DD
004068\tExtended Systems
004069\tPrecision Systems
00406A\tOnset Computer
00406C\tSegala
00406D\tCallOptics
00406E\tComsec
00406F\tKagawa University
004070\tReed-Harper
004071\tProcom Technology
004072\tApple Computer
004078\tCastelle
004079\tGde Systems
00407A\tHolontech Corporation
00407B\tStar Gate Technologies
00407C\tAmeriquest Technologies
00407D\tRPT Internet
00407E\tJato Technologies
00407F\tDSC Communications
004080\tTelxon Corporation
004081\tMicrolabs
004082\tPoint to Point
004083\tSystemland Technology
004084\tYMIR
004085\tEsys.net
004086\tXLAN
004087\tAPC
004088\tSeagate Technology
004089\tLantronix
00408A\tTitan Electronics
00408B\tTrinity Works
00408C\tAxis Communications
00408E\tChester Technology
00408F\tAsk
004090\tAnagram Corporation
004091\tPronet AG
004092\tDynamic Microprocessor Associates
004093\tNovell
004094\tShiva Corporation
004095\tKnowledgeWare
004096\tMitsubishi Electric
004097\tLoughborough Sound Images
004098\tNetworth
004099\tComputer Network Technology
00409A\tNetwork Express
00409B\tCMS Enhancements
00409C\tPivot
00409D\tDiagnostics Plus
00409E\tDigiboard
00409F\tAmeriquest Technologies
0040A2\tControlWare
0040A3\tNetFlix
0040A4\tApple Computer
0040A5\tLeaf Network
0040A6\tCoulter Corporation
0040A7\tRittal-Werk Rudolf Loh GmbH
0040A8\tWirtschaft
0040A9\tDatagate
0040AA\tValmet Automation
0040AB\tAST Research
0040AC\tTelecommunication Systems
0040AD\tApex Data
0040AE\tCompu-Shack Electronic GmbH
0040AF\tDigital Circuit Corp
0040B0\tCentral Point Software
0040B1\tAlfa
0040B2\tNovell
0040B3\tNetAxcess
0040B4\tGlobe Manufacturing Sales
0040B5\tVideocom
0040B6\tCleaner Environments
0040B7\tDigital Products
0040B8\tQMS
0040B9\tCOMSA Corp
0040BA\tGlobe Manufacturing Sales
0040BC\tAmerica Online
0040C1\tTelematique
0040C2\tApple Computer
0040C3\tAiroha Technology Corp
0040C4\tJMR Electronics
0040C5\tHorizon Peripherals
0040C6\tGateway 2000
0040C8\tNorkring AS
0040CA\tMicrosystems Software
0040CC\tSilcom
0040CF\tAgema Infrared Systems
0040D0\tElsinore Aerospace
0040D2\tLandis & Gyr Energy Management
0040D4\tDec-Cezar
0040D8\tNetwork Computing Devices
0040DC\tMitsubishi Electric
0040DF\tDigilog
0040E1\tMaranti Networks
0040E3\tGarrett Communications
0040E5\tSiemons
0040E7\tAironet Communications
0040E9\tOptika Imaging Enterprise
0040EA\tPlainTree Systems
0040EB\tDigilog
0040EE\tOptika Imaging Enterprise
0040EF\tWavephore Networks
0040F0\tAbsolute Value Systems
0040F1\tPrinter Systems Corporation
0040F2\tDrexelbrook Controls
0040F4\tCambex Corporation
0040F5\tAironet Wireless Communications
0040F6\tBytex Corporation
0040F9\tZeitnet
0040FA\tMicrotest
0040FB\tCorporate Network Systems
0040FC\tAntec
0040FD\tLGC Wireless
0040FF\tDigicorp
004CA3\tHewlett Packard
008007\tSiemens AG
008009\tHP
00800D\tDovatron
00800F\tSMC
008010\tOscom International
008019\tDayna Communications
00801B\tHewlett Packard
00801C\tLanCom Systems
00801D\tXced Communications
00801F\tHewlett Packard
008023\tIntegrated Device Technology
008026\tNortel Networks
00802B\tNetWorth
00802D\tXyplex
00802E\tDanpex Corporation
008033\tProteon
008035\tTechland Group
008036\tIntegrated Technology Express
008038\tDEC
00803B\tAMC
00803D\tHigh Technology
00803E\tSol Systems
00803F\tExar Corporation
008041\tDesktop Management Task Force
008043\tProteon
008046\tUniversity of Toronto
008048\tCompaq Computer
004999\tApple Computer
00AA00\tIntel Corporation
00B0AE\tGateway 2000
00C04F\tMicrosoft Corporation
00C0A8\tGVC Corporation
00C0CA\tFoxconn Technology
00D0B7\tIntel Corporation
00E018\tAsustek Computer
00E04C\tRealtek Semiconductor
00E0C5\tBCOM Electronics
00E0EE\tTaiwanate
00E0F1\tINDUS SYSTEMS
00E0F7\tTitan Electronics
00E0F9\tCISCO SYSTEMS
00E0FA\tHewlett Packard
00E0FB\tNovell
00E0FE\tPPT Vision
00E52C\tCircle Computer Research
00E62E\tSeiko Epson Corporation
006008\tCisco Systems
008064\tNoble Net
009027\tHP
00A000\tXerox Corporation
00A024\tHP
00A040\tApple Computer
00A05F\tCalcomp Technology
00A070\tCisco Systems
00A07D\tHP
00A0C9\tIntel Corporation
00A0CC\tLite-On Communications
00A0D1\tGateway 2000
00A0D2\tAllied Telesyn International
001177\tSmartlink Network Systems Limited
001A8C\tTP-Link Technologies
001CF0\tTP-Link Technologies
0021E8\tTP-Link Technologies
0022AB\tTP-Link Technologies
002369\tTP-Link Technologies
002561\tTP-Link Technologies
00265A\tTP-Link Technologies
002D33\tTP-Link Technologies
003092\tTP-Link Technologies
0050F1\tTP-Link Technologies
005043\tTP-Link Technologies
008C54\tTP-Link Technologies
10FEED\tTP-Link Technologies
14CC20\tTP-Link Technologies
18D6C7\tTP-Link Technologies
1C3BF3\tTP-Link Technologies
1CAFF7\tTP-Link Technologies
20F4EB\tTP-Link Technologies
245A4C\tTP-Link Technologies
2C4D54\tTP-Link Technologies
30DE4B\tTP-Link Technologies
34E894\tTP-Link Technologies
3C52A1\tTP-Link Technologies
40167E\tTP-Link Technologies
40A5EF\tTP-Link Technologies
44330C\tTP-Link Technologies
483450\tTP-Link Technologies
50C7BF\tTP-Link Technologies
50FA84\tTP-Link Technologies
549D9E\tTP-Link Technologies
5C628B\tTP-Link Technologies
60E3AC\tTP-Link Technologies
6461BE\tTP-Link Technologies
686FF2\tTP-Link Technologies
70BFCA\tTP-Link Technologies
7491BB\tTP-Link Technologies
78442C\tTP-Link Technologies
78CAE1\tTP-Link Technologies
7C8BCA\tTP-Link Technologies
800A80\tTP-Link Technologies
84163E\tTP-Link Technologies
84A423\tTP-Link Technologies
88B111\tTP-Link Technologies
94D9B3\tTP-Link Technologies
9C4E36\tTP-Link Technologies
A0F3C1\tTP-Link Technologies
A42BB0\tTP-Link Technologies
A860B6\tTP-Link Technologies
AC84C6\tTP-Link Technologies
B08BE8\tTP-Link Technologies
B0487A\tTP-Link Technologies
B44BD2\tTP-Link Technologies
B8F009\tTP-Link Technologies
BC4CB9\tTP-Link Technologies
C025E9\tTP-Link Technologies
C44BD2\tTP-Link Technologies
C4E984\tTP-Link Technologies
C8D3A3\tTP-Link Technologies
CCA223\tTP-Link Technologies
D4EE07\tTP-Link Technologies
D8E0E1\tTP-Link Technologies
DCFEo7\tTP-Link Technologies
E01E8E\tTP-Link Technologies
E2335E\tTP-Link Technologies
E4020B\tTP-Link Technologies
E8DE27\tTP-Link Technologies
EC172F\tTP-Link Technologies
F09FC2\tTP-Link Technologies
F46D04\tTP-Link Technologies
F81A67\tTP-Link Technologies
FC3F7C\tTP-Link Technologies
000726\tCisco Systems
08002B\tDEC
08002E\tPrimos
08002F\tPrime Computer
080032\tTangen Devices
080036\tIntergraph Corporation
080037\tECRC
080038\tData General Corporation
080039\tTechnology Solutions Company
08003B\tTorus Systems
08003D\tUnibus Networks
08003E\tSpectragraphics
08003F\tSun Microsystems
080044\tDEC
080045\tApollo Computer
080046\tSonoma Systems
080047\tSequent Computer Systems
080048\tEBUSA
080049\tUniversal Data Systems
08004C\tEnertec
08004E\tANDNetworks
080051\tExperidata
080056\tStanford University
080058\tDEC
080067\tContrex
080068\tRidgeway Systems
080069\tSilicon Graphics
08006E\tBull
080070\tEnvision Systems
080074\tFluke Networks
080075\tDDE (Dansk Data Elektronik)
080077\tTSL (now Computerized Thermal Imaging)
08007C\tVarian Associates
08007F\tBurough Corporation
080080\tNovell NETWARE
080081\tBAS (Remote Measurement Systems)
080082\tVERITAS DGC
080087\tXyplex
08008B\tThesis
08008D\tXyvision
08008E\tMicros to Mainframes
08008F\tCobra
080090\tHP
080091\tXerox Corporation
080092\tUnisys
080093\tProtocol Interface
080094\tHP
0800A1\tHP
0800AA\tHP
284D5C\tApple
3C15C2\tApple
3C2EFF\tApple
3CCD5C\tApple
3CE072\tApple
400A95\tApple
405D82\tApple
40A6D9\tApple
40CB00\tApple
440010\tApple
4427B5\tApple
4446D9\tApple
4C3C16\tApple
4C57CA\tApple
4C74BF\tApple
4C8D79\tApple
4CB199\tApple
505481\tApple
50EAD6\tApple
5416EB\tApple
5C1D2C\tApple
5C969D\tApple
5CF791\tApple
5CF935\tApple
5CF938\tApple
600308\tApple
60334B\tApple
60D9C7\tApple
60F4F5\tApple
6087CF\tApple
60FB42\tApple
643B9E\tApple
64700A\tApple
647681\tApple
64A5C3\tApple
64E682\tApple
6CE8C9\tApple
6CF049\tApple
705681\tApple
70CD60\tApple
70DEE2\tApple
70E72C\tApple
70F087\tApple
781C30\tApple
7831C1\tApple
78CA39\tApple
78D75F\tApple
78FD94\tApple
7C04D0\tApple
7C6D62\tApple
7CF05F\tApple
7CF3EB\tApple
807D3A\tApple
80BE05\tApple
80E650\tApple
80EDC0\tApple
84789C\tApple
848505\tApple
84B153\tApple
84FC7E\tApple
88194D\tApple
88664C\tApple
886B6E\tApple
88C663\tApple
8C2DAA\tApple
8C7B9D\tApple
8C85C1\tApple
90272E\tApple
907240\tApple
906C3B\tApple
90840D\tApple
90B931\tApple
90FD61\tApple
9483C4\tApple
9C20B5\tApple
9C293F\tApple
9C35EB\tApple
9CF387\tApple
A01867\tApple
A060A6\tApple
A08869\tApple
A4B197\tApple
A4C161\tApple
A4D18C\tApple
A8859B\tApple
A88E24\tApple
A8AFF9\tApple
A8FAD8\tApple
AC29B4\tApple
AC3C0B\tApple
ACF6F7\tApple
B03495\tApple
B065BD\tApple
B0702D\tApple
B4F0AB\tApple
B820E7\tApple
BC3BBF\tApple
BC4CC4\tApple
BC52B7\tApple
BC6778\tApple
BC9FEF\tApple
BCEC5D\tApple
C01ADA\tApple
C08997\tApple
C41297\tApple
C42C03\tApple
C82A14\tApple
C86000\tApple
C8BC C8\tApple
C8D083\tApple
C8E0EB\tApple
CC08E0\tApple
CC785F\tApple
CCF9E8\tApple
D02B20\tApple
D04F7E\tApple
D0A637\tApple
D8004D\tApple
D8BB2C\tApple
D8CF9C\tApple
DC2B2A\tApple
DC2B61\tApple
DC37E2\tApple
DC9B9C\tApple
DCA904\tApple
E00C7F\tApple
E0B52D\tApple
E0C97A\tApple
E0F5C6\tApple
E41F13\tApple
E4251D\tApple
E44BFD\tApple
E4B318\tApple
E4C63D\tApple
E4E0A6\tApple
E8040B\tApple
E8800B\tApple
E89535\tApple
EC3586\tApple
EC852F\tApple
F02475\tApple
F02FA7\tApple
F0B479\tApple
F0D1A9\tApple
F40F24\tApple
F4F15A\tApple
F81EDF\tApple
FC253F\tApple
FC3274\tApple
FCA13E\tApple
FCFC48\tApple
000C29\tVMware
000569\tVMware
005056\tVMware
0C2940\tSamsung Electronics
0C7171\tSamsung Electronics
0CD1DC\tSamsung Electronics
0CE5CC\tSamsung Electronics
1006CD\tSamsung Electronics
1018C1\tSamsung Electronics
107FD9\tSamsung Electronics
10D542\tSamsung Electronics
1227B5\tSamsung Electronics
1426E3\tSamsung Electronics
14499F\tSamsung Electronics
14BB6E\tSamsung Electronics
1492BE\tSamsung Electronics
14568E\tSamsung Electronics
14F42A\tSamsung Electronics
180090\tSamsung Electronics
181A78\tSamsung Electronics
1831BF\tSamsung Electronics
185041\tSamsung Electronics
18E29F\tSamsung Electronics
202566\tSamsung Electronics
207531\tSamsung Electronics
20D390\tSamsung Electronics
20D5BF\tSamsung Electronics
247F3C\tSamsung Electronics
249255\tSamsung Electronics
288314\tSamsung Electronics
28BAB5\tSamsung Electronics
2C0E3D\tSamsung Electronics
2C1C26\tSamsung Electronics
2CA5DC\tSamsung Electronics
2CFCFD\tSamsung Electronics
30C7AE\tSamsung Electronics
3451C9\tSamsung Electronics
34BE00\tSamsung Electronics
38AA3C\tSamsung Electronics
38D40B\tSamsung Electronics
3C62BE\tSamsung Electronics
3C8BFE\tSamsung Electronics
40166F\tSamsung Electronics
40319E\tSamsung Electronics
4093E3\tSamsung Electronics
40D33D\tSamsung Electronics
44783E\tSamsung Electronics
4478BC\tSamsung Electronics
4481CB\tSamsung Electronics
44A733\tSamsung Electronics
50A4C8\tSamsung Electronics
50B7C3\tSamsung Electronics
50CC7B\tSamsung Electronics
50FC9F\tSamsung Electronics
5413DF\tSamsung Electronics
545F5B\tSamsung Electronics
549AEF\tSamsung Electronics
54922A\tSamsung Electronics
54E4BD\tSamsung Electronics
58C38A\tSamsung Electronics
5C2E59\tSamsung Electronics
5C3C27\tSamsung Electronics
5C49EB\tSamsung Electronics
5CA35B\tSamsung Electronics
603BB3\tSamsung Electronics
606BBD\tSamsung Electronics
608F5C\tSamsung Electronics
60A10A\tSamsung Electronics
60D0A9\tSamsung Electronics
64B310\tSamsung Electronics
64B853\tSamsung Electronics
64CC2E\tSamsung Electronics
686E92\tSamsung Electronics
6C2F2C\tSamsung Electronics
6C8336\tSamsung Electronics
6C9400\tSamsung Electronics
70F927\tSamsung Electronics
749DC8\tSamsung Electronics
74F005\tSamsung Electronics
7825AD\tSamsung Electronics
7CE90B\tSamsung Electronics
803088\tSamsung Electronics
806C1B\tSamsung Electronics
80652D\tSamsung Electronics
840B2D\tSamsung Electronics
84119E\tSamsung Electronics
84259C\tSamsung Electronics
8425DB\tSamsung Electronics
847DB4\tSamsung Electronics
884476\tSamsung Electronics
88329B\tSamsung Electronics
8C1ABF\tSamsung Electronics
8C7712\tSamsung Electronics
8CB2CC\tSamsung Electronics
8CC8CD\tSamsung Electronics
8CEBE3\tSamsung Electronics
90218A\tSamsung Electronics
940093\tSamsung Electronics
9499E3\tSamsung Electronics
94D771\tSamsung Electronics
9822EF\tSamsung Electronics
984B4A\tSamsung Electronics
98B0FE\tSamsung Electronics
9C02BA\tSamsung Electronics
9C3AAF\tSamsung Electronics
A0219B\tSamsung Electronics
A0CBFD\tSamsung Electronics
A41140\tSamsung Electronics
A47366\tSamsung Electronics
A4EBD3\tSamsung Electronics
A4F85F\tSamsung Electronics
A83E51\tSamsung Electronics
A88195\tSamsung Electronics
AC5A14\tSamsung Electronics
AC6122\tSamsung Electronics
ACB0D7\tSamsung Electronics
B0721D\tSamsung Electronics
B0D09C\tSamsung Electronics
B47EF9\tSamsung Electronics
B4BCCC\tSamsung Electronics
B4EF39\tSamsung Electronics
B8BC1B\tSamsung Electronics
B8D9CE\tSamsung Electronics
BC20A4\tSamsung Electronics
BC4486\tSamsung Electronics
BC72B1\tSamsung Electronics
BC85CC\tSamsung Electronics
BCF5AC\tSamsung Electronics
C06333\tSamsung Electronics
C0BDD1\tSamsung Electronics
C417FE\tSamsung Electronics
C4731E\tSamsung Electronics
C4AEB2\tSamsung Electronics
C8148E\tSamsung Electronics
C8D3FF\tSamsung Electronics
CC073D\tSamsung Electronics
CC7EDC\tSamsung Electronics
D0176A\tSamsung Electronics
D087E2\tSamsung Electronics
D0DFAA\tSamsung Electronics
D0E140\tSamsung Electronics
D0E7B3\tSamsung Electronics
D4E8B2\tSamsung Electronics
D87195\tSamsung Electronics
D8C4E9\tSamsung Electronics
DC2740\tSamsung Electronics
DC7144\tSamsung Electronics
DCD917\tSamsung Electronics
E016B9\tSamsung Electronics
E031BF\tSamsung Electronics
E04893\tSamsung Electronics
E09855\tSamsung Electronics
E4120D\tSamsung Electronics
E47CF9\tSamsung Electronics
E4F7FB\tSamsung Electronics
E85E89\tSamsung Electronics
E8508B\tSamsung Electronics
EC1F72\tSamsung Electronics
EC9BF3\tSamsung Electronics
F025B7\tSamsung Electronics
F08990\tSamsung Electronics
F09B29\tSamsung Electronics
F0E77E\tSamsung Electronics
F4428F\tSamsung Electronics
F47B5E\tSamsung Electronics
F88FCA\tSamsung Electronics
F8D0AC\tSamsung Electronics
FCA16D\tSamsung Electronics
FCF136\tSamsung Electronics
000C76\tXiaomi
0CF3EE\tXiaomi Communications
14F65A\tXiaomi Communications
18599F\tXiaomi Communications
2C4412\tXiaomi Communications
34CE00\tXiaomi Communications
38A4ED\tXiaomi Communications
40310D\tXiaomi Communications
5068A4\tXiaomi Communications
58000F\tXiaomi Communications
604620\tXiaomi Communications
6470B4\tXiaomi Communications
6C6D39\tXiaomi Communications
8CAAB5\tXiaomi Communications
9C991C\tXiaomi Communications
9CBCE3\tXiaomi Communications
AC2391\tXiaomi Communications
B0E235\tXiaomi Communications
B8E7AA\tXiaomi Communications
C099D4\tXiaomi Communications
CC9543\tXiaomi Communications
D46564\tXiaomi Communications
E47ACF\tXiaomi Communications
F0B429\tXiaomi Communications
FC64BA\tXiaomi Communications
001CB8\tHuawei Technologies
004F1A\tHuawei Technologies
006AE3\tHuawei Technologies
00904C\tHuawei Technologies
040AC4\tHuawei Technologies
04BD70\tHuawei Technologies
0819A6\tHuawei Technologies
082582\tHuawei Technologies
0C37DC\tHuawei Technologies
10C61F\tHuawei Technologies
1098EB\tHuawei Technologies
14B968\tHuawei Technologies
1C8E5C\tHuawei Technologies
20A680\tHuawei Technologies
28754B\tHuawei Technologies
2CB09C\tHuawei Technologies
2CE8DC\tHuawei Technologies
3062F2\tHuawei Technologies
30D17E\tHuawei Technologies
34B354\tHuawei Technologies
38F889\tHuawei Technologies
3C4713\tHuawei Technologies
48DB50\tHuawei Technologies
4C1FCC\tHuawei Technologies
4C8B58\tHuawei Technologies
506015\tHuawei Technologies
546C0E\tHuawei Technologies
58272B\tHuawei Technologies
587F66\tHuawei Technologies
5C4CCA\tHuawei Technologies
5CB495\tHuawei Technologies
5CF51A\tHuawei Technologies
60DE44\tHuawei Technologies
642376\tHuawei Technologies
6497A8\tHuawei Technologies
6CB311\tHuawei Technologies
6CF373\tHuawei Technologies
70723C\tHuawei Technologies
70849B\tHuawei Technologies
70A8E3\tHuawei Technologies
70B3D5\tHuawei Technologies
74882A\tHuawei Technologies
748898\tHuawei Technologies
78008A\tHuawei Technologies
7C60D7\tHuawei Technologies
80717A\tHuawei Technologies
80721C\tHuawei Technologies
80B686\tHuawei Technologies
842B2B\tHuawei Technologies
84A8E4\tHuawei Technologies
8C34FD\tHuawei Technologies
904E2B\tHuawei Technologies
90E2BA\tHuawei Technologies
946A74\tHuawei Technologies
94773E\tHuawei Technologies
98E7F4\tHuawei Technologies
9C28EF\tHuawei Technologies
9CB20E\tHuawei Technologies
9CE374\tHuawei Technologies
A08CF8\tHuawei Technologies
A470D6\tHuawei Technologies
A48DA1\tHuawei Technologies
A4C56E\tHuawei Technologies
A4CAA0\tHuawei Technologies
AC4E91\tHuawei Technologies
B4430D\tHuawei Technologies
B4CD27\tHuawei Technologies
B83095\tHuawei Technologies
B8BC1B\tHuawei Technologies
BC3EA7\tHuawei Technologies
BC754F\tHuawei Technologies
BC7670\tHuawei Technologies
BC967E\tHuawei Technologies
C0D9CD\tHuawei Technologies
C44900\tHuawei Technologies
C47D4F\tHuawei Technologies
C8077C\tHuawei Technologies
C818BB\tHuawei Technologies
C8B5AD\tHuawei Technologies
CC5340\tHuawei Technologies
D065CA\tHuawei Technologies
D0FF98\tHuawei Technologies
D440B0\tHuawei Technologies
D4D2D6\tHuawei Technologies
D8490B\tHuawei Technologies
DC094C\tHuawei Technologies
DC3663\tHuawei Technologies
DCEDE0\tHuawei Technologies
E01CB6\tHuawei Technologies
E028C8\tHuawei Technologies
E0247F\tHuawei Technologies
E024B6\tHuawei Technologies
E0598E\tHuawei Technologies
E4C2D1\tHuawei Technologies
E828A2\tHuawei Technologies
EC388F\tHuawei Technologies
EC4D47\tHuawei Technologies
F02F4B\tHuawei Technologies
F09838\tHuawei Technologies
F412FA\tHuawei Technologies
F47B5E\tHuawei Technologies
F48E38\tHuawei Technologies
F4C714\tHuawei Technologies
F4DCF9\tHuawei Technologies
F8E019\tHuawei Technologies
F8E844\tHuawei Technologies
FC3F7C\tHuawei Technologies
FC48EF\tHuawei Technologies
000BDB\tApple Computer
001451\tApple Computer
001731\tApple Computer
001EC2\tApple Computer
001F5B\tApple Computer
001FF3\tApple Computer
002312\tApple Computer
002500\tApple Computer
0026B9\tApple Computer
002714\tApple Computer
002A5E\tApple Computer
002E7A\tApple Computer
003065\tApple Computer
0030F7\tApple Computer
0050E4\tApple Computer
005558\tApple Computer
005B0F\tApple Computer
006171\tApple Computer
0062D1\tApple Computer
006AC1\tApple Computer
0071A9\tApple Computer
008FA3\tApple Computer
009BD9\tApple Computer
00A040\tApple Computer
00C510\tApple Computer
00C8F8\tApple Computer
00CA2B\tApple Computer
00CE87\tApple Computer
00F7F0\tApple Computer
040CCE\tApple
041537\tApple
041E64\tApple
044BED\tApple
04F7E4\tApple
080007\tApple Computer
100000\tApple
101C0C\tApple
1023EB\tApple
106F3F\tApple
108CCF\tApple
10DDB1\tApple
147AE9\tApple
14920B\tApple
1499E2\tApple
149A20\tApple
14AB01\tApple
14BD61\tApple
14D0DC\tApple
14FED5\tApple
180321\tApple
18AF8F\tApple
18E7F4\tApple
1C36BB\tApple
1C5CF2\tApple
1C9E46\tApple
1CBFC0\tApple
2030F3\tApple
20A2E4\tApple
20C9D0\tApple
24240E\tApple
246AB0\tApple"""

class VendorLookup:
    """
    MAC OUI → vendor name lookup using a local database file.

    Usage:
        vl = VendorLookup()
        name = vl.lookup("aa:bb:cc:dd:ee:ff")  # → "Apple, Inc." or None
        name = vl.lookup("AA-BB-CC-DD-EE-FF")  # same — format normalized
        vl.is_likely_hypervisor(name)          # → True if VM platform
    """

    def __init__(self, oui_file: str = _DEFAULT_OUI_FILE):
        self._oui_file = oui_file
        self._db: Dict[str, str] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, mac: str) -> Optional[str]:
        """
        Return vendor name for a MAC address, or None if unknown.

        Args:
            mac: MAC in any common format:
                 aa:bb:cc:dd:ee:ff  (colon-separated)
                 AA-BB-CC-DD-EE-FF  (hyphen-separated)
                 AABBCCDDEEFF       (no separator)

        Returns:
            Vendor name string, or None if OUI not in database.
        """
        if not mac:
            return None

        oui = self._normalize_oui(mac)
        if not oui:
            return None

        vendor = self._db.get(oui)
        if vendor:
            logger.debug(f"OUI {oui} → {vendor}")
        else:
            logger.debug(f"OUI {oui} → unknown")

        return vendor

    def lookup_batch(self, macs: list) -> Dict[str, Optional[str]]:
        """
        Lookup multiple MACs in one call.

        Args:
            macs: List of MAC address strings.

        Returns:
            Dict of {mac: vendor_or_None}.
        """
        return {mac: self.lookup(mac) for mac in macs}

    def is_likely_hypervisor(self, vendor: Optional[str]) -> bool:
        """
        Return True if a vendor string belongs to a known virtualization
        platform (VMware, VirtualBox, Hyper-V, QEMU, Xen, Parallels).

        This is purely informational — it does NOT change any trust
        decision. A device tagged True is still evaluated by trust_engine
        exactly as any other device would be; this flag only lets
        alert_manager / CLI annotate the display with a human-readable
        hint ("possible VM on this machine") so a bridged VM you run
        yourself doesn't read as a mystery intruder at a glance.

        Args:
            vendor: Vendor name string (from lookup() or scanner output).
                    Safe to pass None or "" — returns False.

        Returns:
            True if the vendor string matches a known hypervisor marker.
        """
        if not vendor:
            return False
        vendor_lower = vendor.lower()
        return any(marker in vendor_lower for marker in _HYPERVISOR_VENDOR_MARKERS)

    def is_loaded(self) -> bool:
        """Return True if the OUI database loaded successfully."""
        return len(self._db) > 0

    def entry_count(self) -> int:
        """Return number of OUI entries loaded."""
        return len(self._db)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _normalize_oui(self, mac: str) -> Optional[str]:
        """
        Extract and normalize the OUI (first 3 bytes) from any MAC format.
        Returns uppercase 6-char hex string, e.g. 'A4C138'.
        """
        try:
            # Strip separators and take first 6 hex chars
            clean = re.sub(r'[^0-9A-Fa-f]', '', mac)
            if len(clean) < 6:
                return None
            return clean[:6].upper()
        except Exception:
            return None

    def _load(self) -> None:
        """Load OUI database from file, writing bundled data if missing."""
        # Write bundled data if file doesn't exist
        if not os.path.exists(self._oui_file):
            self._write_bundled()

        try:
            loaded = 0
            with open(self._oui_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("\t", 1)
                    if len(parts) == 2:
                        oui    = re.sub(r'[^0-9A-Fa-f]', '', parts[0])[:6].upper()
                        vendor = parts[1].strip()
                        if oui and vendor:
                            self._db[oui] = vendor
                            loaded += 1

            logger.info(
                f"VendorLookup loaded {loaded} OUI entries from {self._oui_file}"
            )

        except Exception as e:
            logger.error(f"Failed to load OUI database: {e}")

    def _write_bundled(self) -> None:
        """Write the bundled OUI data to the database file."""
        try:
            os.makedirs(
                os.path.dirname(self._oui_file)
                if os.path.dirname(self._oui_file) else ".",
                exist_ok=True,
            )
            with open(self._oui_file, "w", encoding="utf-8") as f:
                f.write("# Cerberus v2 — OUI vendor database\n")
                f.write("# Format: OUI<TAB>VENDOR\n")
                f.write("# Update: python -m cerberus.detection.vendor_lookup --update\n\n")
                f.write(_BUNDLED_OUI)
            logger.info(f"Bundled OUI database written to {self._oui_file}")
        except Exception as e:
            logger.warning(f"Could not write OUI file: {e} — using in-memory lookup")
            # Load from bundled string directly
            for line in _BUNDLED_OUI.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split("\t", 1)
                if len(parts) == 2:
                    oui    = re.sub(r'[^0-9A-Fa-f]', '', parts[0])[:6].upper()
                    vendor = parts[1].strip()
                    if oui and vendor:
                        self._db[oui] = vendor


# ---------------------------------------------------------------------------
# Standalone smoke-test + update utility
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    vl = VendorLookup()
    print(f"\nOUI database loaded: {vl.entry_count()} entries\n")

    test_macs = [
        ("00:17:7c:ba:e0:f5", "Smartlink (your router)"),
        ("50:5a:65:75:3a:31", "Unknown — test"),
        ("9a:8d:c5:08:df:6f", "Randomized MAC — test"),
        ("52:5a:ce:f5:90:97", "Randomized MAC — test"),
        ("A4:C1:38:00:00:00", "Apple"),
        ("00:1A:8C:00:00:00", "TP-Link"),
        ("00:0C:29:00:00:00", "VMware"),
        ("00:50:56:00:00:00", "VMware"),
        ("B8:27:EB:00:00:00", "Raspberry Pi Foundation"),
        ("DC:A6:32:00:00:00", "Raspberry Pi Foundation"),
    ]

    print(f"{'MAC ADDRESS':<22} {'EXPECTED':<30} {'RESULT':<30} {'HYPERVISOR?'}")
    print("-" * 100)
    for mac, expected in test_macs:
        result = vl.lookup(mac) or "unknown"
        is_vm = vl.is_likely_hypervisor(result)
        print(f"{mac:<22} {expected:<30} {result:<30} {is_vm}")