/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  // check Ether
  if (packet.size() < sizeof(struct ethernet_hdr))
  {
    goto InvalidEther;
  }
  struct ethernet_hdr* eHdr = (struct ethernet_hdr*)packet.data();

  const auto dst = eHdr->ether_dhost;
  const auto iface = findIfaceByName(inIface);
  if (memcmp(dst, iface->addr.data(), ETHER_ADDR_LEN) &&
    (dst[0] & dst[1] & dst[2] & dst[3] & dst[4] & dst[5]) != 0xff)
  {
    goto InvalidEther;
  }

  uint16_t eType = ethertype(eHdr);
  switch (eType)
  {

  case ethertype_ip:
    std::cerr << "Handling IPv4 Packet..." << std::endl;
    handleIPv4(packet, inIface);
    break;

  case ethertype_arp:
    std::cerr << "Handling ARP Packet..." << std::endl;
    handleArp(packet, inIface);
    break;

  default:
    goto InvalidEther;
    break;
  }

InvalidEther:
  {
    std::cerr << "Invalid Ether Header" << std::endl;
    return;
  }
}

void
SimpleRouter::handleIPv4(const Buffer& packet, const std::string& inIface)
{
  if (packet.size() != sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr))
  {
    goto InvalidIPv4;
  }
  struct ip_hdr* iHdr = (struct ip_hdr*)(packet.data() +��sizeof(struct ethernet_hdr));
  const auto checksum = iHdr->ip_sum;
  iHdr->ip_sum = 0;
  if (cksum(iHdr, sizeof(struct ip_hdr)) != checksum)
  {
    iHdr->ip_sum = checksum;
    goto InvalidIPv4;
  }
  iHdr->ip_sum = checksum;

  const auto iface = findIfaceByIp(iHdr->ip_dst);
  if (iface) // forwarding
  {
    // dispatch IPv4
    sendIPv4(packet, inIface);
  }
  else // dst to router
  {
    handleICMP(packet);
  }

InvalidIPv4:
  {
    std::cerr << "Invalid IPv4 packet" << std::endl;
    return;
  }
}

void
SimpleRouter::handleArp(const Buffer& packet, const std::string& inIface)
{
  if (packet.size() != sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr))
  {
    goto InvalidArp;
  }
  struct arp_hdr* aHdr = (struct arp_hdr*)(packet.data() + sizeof(struct ethernet_hdr));
  const auto iface = findIfaceByName(inIface);

  if (aHdr->arp_tip != iface->ip)
  {
    std::cerr << "ARP IP and interface does not match" << std::endl;
    return;
  }

  if (ntohs(aHdr->arp_hrd) != arp_hrd_ethernet ||
      ntohs(aHdr->arp_pro) != 0x800 ||
      aHdr->arp_hln != 0x06 ||
      aHdr->arp_pln != 0x04)
  {
    goto InvalidArp;
  }

  switch (ntohs(aHdr->arp_op))
  {
  case arp_op_request:
    sendArpReply(packet, inIface);
    break;
  case arp_op_reply:
    struct arp_hdr* aHdrR = (struct arp_hdr*)(packet.data() + sizeof(struct ethernet_hdr));
    const auto ip = aHdrR->sip;
    Buffer mac(aHdrR->arp_sha, aHdrR->arp_sha + ETHER_ADDR_LEN);
    auto request = m_arp.insertArpEntry(mac, ip);
    if (request)
    {
      for (auto p : request->packets)
      {
        handlePacket(p.packet, p.iface);
      }
      m_arp.removeRequest(request);
    }
    break;

  default:
    goto InvalidArp;
    break;
  }

InvalidArp:
  {
    std::cerr << "Invalid ARP packet" << std::endl;
    return;
  }
}

void
SimpleRouter::handleICMP(const Buffer& packet)
{

  // tcp or udp
  if (iHdr->ip_p != ip_protocol_icmp)
  {
    // icmp unreachable
    sendICMP(packet, icmp_type_unreachable, icmp_code_port_unreachable);
    return;
  }

  if (packet.size() < sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr))
  {
    goto InvalidICMP;
  }

  // ??? todo
  struct icmp_hdr* icHdr = (struct icmp_hdr*)(packet.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
  const auto checksum = icHdr->icmp_sum;
  icHdr->icmp_sum = 0;
  if (cksum(icHdr, packet.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr)) != checksum)
  {
    icHdr->icmp_sum = checksum;
    goto InvalidICMP;
  }
  icHdr->icmp_sum = checksum;

  if (icHdr->icmp_type == icmp_type_echo && hICMP->icmp_code == icmp_code_echo)
  {
    // replyIcmpEchoReply
    sendICMP(packet, icmp_type_echo_reply, icmp_type_echo_reply);
  }

InvalidICMP:
  {
    std::cerr << "Invalid ICMP packet" << std::endl;
    return;
  }
}

void
SimpleRouter::sendArpRequest(uint32_t ip)
{
  Buffer request(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr));
  struct ethernet_hdr* eHdr = (struct ethernet_hdr*)(request.data());
  struct arp_hdr* aHdr = (struct arp_hdr*)((uint8_t*)eHdr + sizeof(struct ethernet_hdr));
  const auto entry = m_routingTable.lookup(ip);
  const auto outIface = findIfaceByName(entry.ifName);

  memcpy(eHdr->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
  memset(eHdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  eHdr->ether_type = htons(ethertype_arp);

  memcpy(aHdr->arp_sha, outIface->addr.data(), ETHER_ADDR_LEN);
  memset(aHdr->arp_tha, 0xff, ETHER_ADDR_LEN);
  aHdr->arp_hrd = htons(arp_hrd_ethernet);
  aHdr->arp_pro = htons(arp_pro_ipv4);
  aHdr->arp_hln = ARP_HW_LEN;
  aHdr->arp_pln = ARP_PORT_LEN;
  aHdr->arp_op = htons(arp_op_request);
  aHdr->arp_sip = outIface->ip;
  aHdr->arp_tip = ip;
  
  sendPacket(request, outIface->name);
}

void
SimpleRouter::sendArpReply(const Buffer& packet, const std::string& inIface)
{
  Buffer reply(packet);
  struct ethernet_hdr* eHdrR = (struct ethernet_hdr*)(reply.data());
  struct arp_hdr* aHdrR = (struct arp_hdr*)((uint8_t*)eHdrR + sizeof(struct ethernet_hdr));

  struct ethernet_hdr* eHdr = (struct ethernet_hdr*)(packet.data());
  struct arp_hdr* aHdrR = (struct arp_hdr*)((uint8_t*)eHdr + sizeof(struct ethernet_hdr));
  const auto iface = findIfaceByName(inIface);

  memcpy(eHdrR->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
  memcpy(eHdrR->ether_dhost, eHdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(aHdrR->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
  memcpy(aHdrR->arp_tha, aHdr->arp_sha, ETHER_ADDR_LEN);
  aHdrR->arp_sip = aHdr->arp_tip;
  aHdrR->arp_tip = aHdr->arp_sip;
  aHdrR->arp_op = htons(arp_op_reply);

  sendPacket(reply, iface->name);
}

void
SimpleRouter::sendICMP(const Buffer& packet, const uint8_t& icmp_type, const uint8_t& icmp_code)
{
  Buffer reply(packet);
  struct ethernet_hdr* eHdrR = (struct ethernet_hdr*)(reply.data());
  struct ip_hdr* iHdrR = (struct ip_hdr*)((uint8_t*)eHdrR + sizeof(struct ethernet_hdr);
  struct icmp_t3_hdr icHdrR = (struct icmp_t3_hdr*)((uint8_t)iHdrR + sizeof(struct ip_hdr));

  struct ethernet_hdr* eHdr = (struct ethernet_hdr*)(packet.data());
  struct ip_hdr* iHdr = (struct ip_hdr*)((uint8_t*)eHdr + sizeof(struct ether_hdr));
  const auto entry = m_routingTable.lookup(iHdr->ip_src);
  const auto outIface = findIfaceByName(entry.ifName);

  memcpy(eHdrR->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
  memcpy(eHdrR->ether_dhost, eHdr->ether_shost, ETHER_ADDR_LEN);
  eHdrR->ether_type = htons(ethertype_ip);

  iHdrR->ip_id = 0;
  iHdrR->ip_p = ip_protocol_icmp;
  iHdrR->ip_ttl = IP_TTL;
  iHdrR->ip_sum = 0;
  iHdrR->ip_src = outIface->ip;
  iHdrR->ip_dst = iHdr->ip_src;
  iHdrR->ip_sum = cksum(iHdrR, sizeof(struct ip_hdr));

  icHdrR->icmp_type = icmp_type;
  icHdrR->icmp_code = icmp_code;
  if (icmp_type == icmp_type_time_exceeded || icmp_type == icmp_type_unreachable)
  {
    memcpy((uint8_t*)icHdrR->data, (uint8_t*)iHdr, ICMP_DATA_SIZE);
  }
  icHdrR->icmp_sum = 0;
  icHdrR->icmp_sum = cksum(icHdrR, packet.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));

  sendPacket(reply, outIface);
}

void
SimpleRouter::sendIPv4(const Buffer& packet, const std::string& inIface)
{
  struct ip_hdr* iHdr = (struct ip_hdr*)(packet.data() + sizeof(struct ethernet_hdr));
  if (iHdr->ip_ttl <= 1)
  {
    sendICMP(packet, icmp_type_time_exceeded, icmp_code_ttl_exceeded);
    return;
  }
  RoutingTableEntry = rtEntry;
  try
  {
    rtEntry = m_routingTable.lookup(iHdr->ip_dst);
  }
  catch(const std::runtime_error& e)
  {
    std::cerr << e.what() << std::endl;
    sendICMP(packet, icmp_type_unreachable, icmp_code_net_unreachable);
  }

  const auto aEntry = m_arp.lookup(rtEntry.gw);
  if (!aEntry)
  {
    m_arp.queueRequest(iHdr->ip_dst, packet, inIface);
    return;
  }

  Buffer buf = packet;
  struct ethernet_hdr* eHdr = (struct ethernet_hdr*)(buf.data());
  struct ip_hdr* iHdrS = (struct ip_hdr*)((uint8_t*)eHdr + sizeof(struct ethernet_hdr));
  const auto outIface = findIfaceByName(rtEntry.ifName);

  memcpy(eHdr->ether_shost, outIface->addr.data(), ETHER_ADDR_LEN);
  memcpy(eHdr->ether_dhost, aEntry->mac.data(), ETHER_ADDR_LEN);

  iHdrS->ip_ttl--;
  iHdrS->ip_sum = 0;
  iHdrS->ip_sum = cksum(iHdrS, sizeof(struct ip_hdr);
  sendPacket(buf, outIface->name);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
