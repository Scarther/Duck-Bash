# Chapter 02: WiFi Pineapple - Assessment Quiz

## Instructions
- Choose the best answer for each question
- Answers are provided at the end
- Passing score: 70% (14/20 correct)

---

## Section A: Fundamentals (5 questions)

### Q1. What is the primary attack the WiFi Pineapple is known for?
- A) Bluetooth sniffing
- B) Evil Twin / Rogue AP attacks
- C) USB keystroke injection
- D) Cellular interception

### Q2. What does KARMA attack exploit?
- A) WPA3 vulnerabilities
- B) Client probe requests for previously connected networks
- C) WEP encryption weaknesses
- D) DNS cache poisoning

### Q3. Which protocol is used for capturing WPA handshakes?
- A) EAPOL (Extensible Authentication Protocol over LAN)
- B) HTTP
- C) SNMP
- D) RADIUS

### Q4. What is a "captive portal" in the context of WiFi attacks?
- A) A firewall rule
- B) A web page that intercepts clients for credential harvesting
- C) A network monitoring tool
- D) An encrypted tunnel

### Q5. What is the purpose of a deauthentication attack?
- A) Permanently disconnect a client
- B) Force clients to reconnect, enabling handshake capture
- C) Encrypt network traffic
- D) Block all WiFi signals

---

## Section B: Attack Techniques (5 questions)

### Q6. What does PMKID capture allow?
- A) Decrypt all traffic on the network
- B) Crack WPA without capturing a full 4-way handshake
- C) Clone MAC addresses
- D) Bypass 802.1X authentication

### Q7. Which tool is commonly used for capturing WiFi handshakes?
- A) Nmap
- B) Airodump-ng
- C) Wireshark
- D) Netcat

### Q8. What is an "Evil Twin" attack?
- A) Running two network adapters
- B) Creating a fake AP that mimics a legitimate one
- C) Dual-band jamming
- D) Cloning a client device

### Q9. What frequency bands does the WiFi Pineapple Mark VII support?
- A) 2.4 GHz only
- B) 5 GHz only
- C) Both 2.4 GHz and 5 GHz
- D) 6 GHz (WiFi 6E)

### Q10. What information can be gathered from client probe requests?
- A) The client's password
- B) SSIDs of networks the client previously connected to
- C) The client's IP address
- D) The client's MAC address history

---

## Section C: Defense (5 questions)

### Q11. What is a Wireless Intrusion Detection System (WIDS)?
- A) A tool that encrypts WiFi traffic
- B) A system that detects rogue APs and wireless attacks
- C) A firewall for wireless networks
- D) A VPN for WiFi

### Q12. How can you detect an Evil Twin attack?
- A) Check signal strength anomalies and BSSID changes
- B) Only use WEP encryption
- C) Disable WiFi completely
- D) Use longer passwords

### Q13. What protection does 802.11w provide?
- A) Faster data transfer
- B) Protection for management frames against deauth attacks
- C) Automatic password rotation
- D) WPA4 encryption

### Q14. Which is the BEST defense against KARMA attacks?
- A) Use hidden SSIDs
- B) Configure clients not to auto-connect to open networks
- C) Use MAC filtering
- D) Enable WPS

### Q15. What should enterprises implement to detect rogue access points?
- A) VPN on all devices
- B) WIPS (Wireless Intrusion Prevention System)
- C) Stronger passwords
- D) Guest networks

---

## Section D: Practical Application (5 questions)

### Q16. What command sets a wireless interface to monitor mode?
- A) `ifconfig wlan0 monitor`
- B) `airmon-ng start wlan0`
- C) `iwconfig wlan0 monitor`
- D) `netsh wlan set mode=monitor`

### Q17. Which file contains captured handshakes in aircrack-ng format?
- A) .csv
- B) .cap or .pcap
- C) .txt
- D) .hccapx

### Q18. What tool is used to crack WPA handshakes with GPU acceleration?
- A) John the Ripper
- B) Hashcat
- C) Hydra
- D) Medusa

### Q19. What Hashcat mode is used for WPA/WPA2?
- A) -m 0
- B) -m 1000
- C) -m 22000
- D) -m 5600

### Q20. What is the purpose of PineAP on the WiFi Pineapple?
- A) Remote access
- B) Broadcasting multiple SSIDs and managing client associations
- C) Traffic encryption
- D) Firmware updates

---

## Answer Key

<details>
<summary>Click to reveal answers</summary>

| Question | Answer | Explanation |
|----------|--------|-------------|
| Q1 | B | WiFi Pineapple is known for Evil Twin/Rogue AP attacks |
| Q2 | B | KARMA responds to client probes for any SSID |
| Q3 | A | EAPOL frames contain the 4-way handshake |
| Q4 | B | Captive portals intercept web traffic for credential collection |
| Q5 | B | Deauth forces reconnection to capture handshake |
| Q6 | B | PMKID allows cracking without full handshake |
| Q7 | B | Airodump-ng captures handshakes |
| Q8 | B | Evil Twin mimics a legitimate AP |
| Q9 | C | Mark VII supports both 2.4 and 5 GHz |
| Q10 | B | Probe requests reveal previously connected SSIDs |
| Q11 | B | WIDS detects rogue APs and attacks |
| Q12 | A | Monitor for BSSID changes and signal anomalies |
| Q13 | B | 802.11w protects management frames |
| Q14 | B | Prevent auto-connect to open networks |
| Q15 | B | WIPS actively monitors and prevents attacks |
| Q16 | B | airmon-ng start wlan0 enables monitor mode |
| Q17 | B | .cap/.pcap files contain captured packets |
| Q18 | B | Hashcat has GPU acceleration support |
| Q19 | C | Mode 22000 is for WPA/WPA2 |
| Q20 | B | PineAP manages SSIDs and associations |

**Passing Score: 14/20 (70%)**

</details>

---

## Scoring

- **18-20 correct**: Expert level - Ready for red team wireless ops
- **14-17 correct**: Proficient - Good understanding of WiFi attacks
- **10-13 correct**: Developing - Review wireless fundamentals
- **Below 10**: Needs improvement - Re-study Chapter 02 material

---

[← Chapter 01 Quiz](./Chapter_01_Quiz.md) | [Back to Assessments](./README.md) | [Chapter 03 Quiz →](./Chapter_03_Quiz.md)
