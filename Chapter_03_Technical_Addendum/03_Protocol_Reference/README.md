# Protocol Reference

## USB Human Interface Device (HID)

### HID Report Descriptor
```
USB HID Keyboard Report (8 bytes):
┌────────────────────────────────────────────────────────┐
│ Byte 0: Modifier Keys                                  │
│   Bit 0: Left Ctrl    Bit 4: Right Ctrl               │
│   Bit 1: Left Shift   Bit 5: Right Shift              │
│   Bit 2: Left Alt     Bit 6: Right Alt (AltGr)        │
│   Bit 3: Left GUI     Bit 7: Right GUI                │
├────────────────────────────────────────────────────────┤
│ Byte 1: Reserved (0x00)                                │
├────────────────────────────────────────────────────────┤
│ Bytes 2-7: Key codes (up to 6 simultaneous keys)       │
│   0x00 = No key                                        │
│   0x04-0x1D = A-Z                                      │
│   0x1E-0x27 = 1-0                                      │
│   0x28 = Enter                                         │
│   0x29 = Escape                                        │
│   0x2A = Backspace                                     │
│   0x2B = Tab                                           │
│   0x2C = Space                                         │
└────────────────────────────────────────────────────────┘
```

### Common HID Key Codes
| Key | Code | Key | Code |
|-----|------|-----|------|
| A | 0x04 | 1 | 0x1E |
| B | 0x05 | 2 | 0x1F |
| C | 0x06 | 3 | 0x20 |
| ... | ... | ... | ... |
| Z | 0x1D | 0 | 0x27 |
| Enter | 0x28 | Space | 0x2C |
| Escape | 0x29 | Tab | 0x2B |
| F1-F12 | 0x3A-0x45 | Insert | 0x49 |
| Delete | 0x4C | Home | 0x4A |
| End | 0x4D | PgUp | 0x4B |
| PgDn | 0x4E | Right | 0x4F |
| Left | 0x50 | Down | 0x51 |
| Up | 0x52 | PrintScr | 0x46 |

### USB Descriptors
```c
// Device Descriptor
struct usb_device_descriptor {
    uint8_t  bLength;           // 18
    uint8_t  bDescriptorType;   // 1 (Device)
    uint16_t bcdUSB;            // 0x0200 (USB 2.0)
    uint8_t  bDeviceClass;      // 0 (Defined at interface)
    uint8_t  bDeviceSubClass;   // 0
    uint8_t  bDeviceProtocol;   // 0
    uint8_t  bMaxPacketSize0;   // 64
    uint16_t idVendor;          // VID
    uint16_t idProduct;         // PID
    uint16_t bcdDevice;         // Device version
    uint8_t  iManufacturer;     // String index
    uint8_t  iProduct;          // String index
    uint8_t  iSerialNumber;     // String index
    uint8_t  bNumConfigurations;// 1
};

// HID Interface Descriptor
struct usb_hid_descriptor {
    uint8_t  bLength;           // 9
    uint8_t  bDescriptorType;   // 0x21 (HID)
    uint16_t bcdHID;            // 0x0111 (HID 1.11)
    uint8_t  bCountryCode;      // 0
    uint8_t  bNumDescriptors;   // 1
    uint8_t  bReportDescType;   // 0x22 (Report)
    uint16_t wReportDescLength; // Report descriptor size
};
```

---

## 802.11 Wireless Protocol

### Frame Format
```
┌─────────────────────────────────────────────────────────────┐
│                   802.11 MAC FRAME                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│ ┌──────┬─────────┬──────┬──────┬──────┬──────┬──────┬─────┐│
│ │Frame │Duration/│Addr1 │Addr2 │Addr3 │Seq   │Addr4 │Frame││
│ │Control│   ID   │      │      │      │Ctrl  │      │Body ││
│ │2 bytes│2 bytes │6 byte│6 byte│6 byte│2 byte│6 byte│0-2312│
│ └──────┴─────────┴──────┴──────┴──────┴──────┴──────┴─────┘│
│                                                              │
│ Frame Control Field:                                         │
│ ┌────┬────┬────┬────┬────┬────┬────┬────┬────┬────┬────┐   │
│ │Prot│Type│Subtype  │ToDS│FrDS│More│Retry│Pwr │More│WEP │   │
│ │Ver │    │         │    │    │Frag│     │Mgmt│Data│    │   │
│ │2bit│2bit│4 bits   │1bit│1bit│1bit│1bit │1bit│1bit│1bit│   │
│ └────┴────┴────┴────┴────┴────┴────┴────┴────┴────┴────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Frame Types
| Type | Subtype | Name |
|------|---------|------|
| 00 | 0000 | Association Request |
| 00 | 0001 | Association Response |
| 00 | 0100 | Probe Request |
| 00 | 0101 | Probe Response |
| 00 | 1000 | Beacon |
| 00 | 1010 | Disassociation |
| 00 | 1011 | Authentication |
| 00 | 1100 | Deauthentication |
| 01 | 1011 | RTS |
| 01 | 1100 | CTS |
| 01 | 1101 | ACK |
| 10 | 0000 | Data |
| 10 | 0100 | Null Function |
| 10 | 1000 | QoS Data |

### WPA 4-Way Handshake
```
┌─────────────┐                        ┌─────────────┐
│   Client    │                        │     AP      │
└──────┬──────┘                        └──────┬──────┘
       │                                      │
       │  ◄───────── Message 1 ────────────  │
       │     ANonce (AP Nonce)                │
       │                                      │
       │  ─────────── Message 2 ────────────▶ │
       │     SNonce (Station Nonce)           │
       │     MIC (Message Integrity Code)     │
       │                                      │
       │  ◄───────── Message 3 ────────────  │
       │     ANonce, MIC, GTK                 │
       │     (Group Temporal Key)             │
       │                                      │
       │  ─────────── Message 4 ────────────▶ │
       │     MIC (Acknowledgment)             │
       │                                      │
       ▼                                      ▼
   [PTK Installed]                    [PTK Installed]

   Key Derivation:
   PTK = PRF(PMK, ANonce, SNonce, AP_MAC, STA_MAC)
   PMK = PBKDF2(Passphrase, SSID, 4096, 256)
```

### EAPOL Frame Format
```
┌─────────────────────────────────────────────────────────────┐
│                    EAPOL KEY FRAME                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│ ┌────────┬────────┬──────────┬───────────┬────────────────┐│
│ │Protocol│Packet  │Packet    │Descriptor │Key             ││
│ │Version │Type    │Body Len  │Type       │Information     ││
│ │1 byte  │1 byte  │2 bytes   │1 byte     │2 bytes         ││
│ └────────┴────────┴──────────┴───────────┴────────────────┘│
│                                                              │
│ Key Information Bits:                                        │
│   Bit 3: Key Type (0=Group, 1=Pairwise)                     │
│   Bit 6: Install                                             │
│   Bit 7: Key ACK                                             │
│   Bit 8: Key MIC                                             │
│   Bit 9: Secure                                              │
│   Bit 10: Error                                              │
│   Bit 11: Request                                            │
│   Bit 12: Encrypted Key Data                                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Deauthentication Frame

### Frame Structure
```
Deauthentication Frame:
┌──────────────┬─────────────┬──────────────┬──────────────┐
│ Frame Control│ Duration    │ Destination  │ Source       │
│ 0x00C0       │ 0x0000      │ 6 bytes      │ 6 bytes      │
└──────────────┴─────────────┴──────────────┴──────────────┘
┌──────────────┬──────────────┬──────────────┐
│ BSSID        │ Seq Control  │ Reason Code  │
│ 6 bytes      │ 2 bytes      │ 2 bytes      │
└──────────────┴──────────────┴──────────────┘

Reason Codes:
  1 = Unspecified
  2 = Previous auth no longer valid
  3 = Deauth leaving BSS
  4 = Disassoc due to inactivity
  5 = Disassoc because AP can't handle STAs
  6 = Class 2 frame from non-authenticated STA
  7 = Class 3 frame from non-associated STA
```

---

## Probe Request/Response

### Probe Request
```
Information Elements:
┌──────────────────────────────────────────────────────────┐
│ Element ID │ Length │ Data                               │
├────────────┼────────┼────────────────────────────────────┤
│ 0 (SSID)   │ 0-32   │ Network name (or empty for any)   │
│ 1 (Rates)  │ 1-8    │ Supported rates                    │
│ 50 (Ext)   │ varies │ Extended supported rates           │
│ 45 (HT)    │ 26     │ HT Capabilities                    │
│ 127 (Ext)  │ varies │ Extended capabilities              │
└──────────────────────────────────────────────────────────┘
```

### Probe Response
```
Fixed Fields:
├── Timestamp: 8 bytes
├── Beacon Interval: 2 bytes
├── Capability Info: 2 bytes

Information Elements:
├── SSID (ID=0)
├── Supported Rates (ID=1)
├── DS Parameter Set (ID=3): Channel
├── Country (ID=7)
├── RSN (ID=48): Security info
├── Vendor Specific (ID=221)
└── Extended Capabilities
```

---

## RADIUS/EAP Protocol

### EAP Packet Format
```
┌──────────┬──────────┬──────────┬──────────────────────┐
│ Code     │ ID       │ Length   │ Data                 │
│ 1 byte   │ 1 byte   │ 2 bytes  │ Variable             │
└──────────┴──────────┴──────────┴──────────────────────┘

Codes:
  1 = Request
  2 = Response
  3 = Success
  4 = Failure

EAP Types:
  1 = Identity
  4 = MD5-Challenge
  13 = EAP-TLS
  21 = EAP-TTLS
  25 = PEAP
  43 = EAP-FAST
```

### RADIUS Packet Format
```
┌──────────┬──────────┬──────────┬──────────────────────┐
│ Code     │ ID       │ Length   │ Authenticator        │
│ 1 byte   │ 1 byte   │ 2 bytes  │ 16 bytes             │
└──────────┴──────────┴──────────┴──────────────────────┘
┌────────────────────────────────────────────────────────┐
│ Attributes (Variable)                                  │
│   ┌──────────┬──────────┬──────────────────────────┐  │
│   │ Type     │ Length   │ Value                    │  │
│   │ 1 byte   │ 1 byte   │ Variable                 │  │
│   └──────────┴──────────┴──────────────────────────┘  │
└────────────────────────────────────────────────────────┘

RADIUS Codes:
  1 = Access-Request
  2 = Access-Accept
  3 = Access-Reject
  11 = Access-Challenge
```

---

[← Back to Technical Addendum](../README.md) | [Next: USB VID/PID Database →](../04_USB_VID_PID_Database/)
