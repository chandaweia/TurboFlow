#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <set>
#include <tuple>

#include <math.h>
#include <stdlib.h>

#include <iostream>
#include <fstream>
#include <cstring>
#include <sstream> // for ostringstream
#include <vector>
#include <sstream>
#include <iomanip>
using namespace std;

// Generate 
// Dump the microflow records the TurboFlow microflow generator 
// would send to the switch CPU. 
// parameters: 
// 1 -- input pcap trace (expects IP trace, change traceType for eth)
// 2 -- height of the hash table (number of flow slots)

// g++ turboflow.cpp -o turboflow -lpcap -std=c++11
// ./turboflow ~/datasets/caida2015/caida2015_02_dirA.pcap 13

// Define a type alias for the 5-tuple that uniquely identifies a flow
using FlowTuple = tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>;

uint64_t dbg_packetCt;
uint64_t dbg_evictCt;
uint64_t total_flowCt;
using Flow = tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>;
set<FlowTuple> uniqueFlows;

uint64_t dbg_collisionCt;
uint64_t dbg_removeFlowCt;
uint64_t dbg_addFlowCt;

// Static options.
#define traceType 1 // 0 = ethernet pcap, 1 = ip4v pcap (i.e., caida datasets)
#define KEYLEN 12 // key length in bytes.
#define STOP_CT 10000000 // stop execution after STOP_CT packets.
#define LOG_CT 1000000 // print info every LOG_CT packets.

char nullKey[KEYLEN] = { 0 };

// Internal structures. 
struct MicroflowRecord {
  char key[KEYLEN];
  uint32_t byteCount;  
  uint16_t packetCount;  
};

struct Metadata {
  std::string key;
  unsigned hash;
  uint32_t byteCount;  
  uint64_t ts;
};

// Global state. 
uint32_t TABLELEN;
uint32_t packetSinceEvict = 0;
uint32_t packetsPerEvict;
// Table of hash -> keys.
char ** keyTable;
// Table of hash -> byte counts.
uint32_t * byteCountTable;
// Table of hash -> packet counts.
uint16_t * packetCountTable;

uint64_t startTs = 0;
uint64_t dur = 0;

// init global state for turboflow.
void stateInit(int tableSize);

// Handle packets.
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);

// update microflow tables. 
void updateTables(Metadata md);

// Write a micro flow record to a file or std out.
void dumpMicroflowRecord(MicroflowRecord mfr, bool collision);

// Helper functions.
void printHeader();
unsigned simpleHash(const char* s, int len, int maxHashVal);
std::string getKey(const struct ip* ipHeader, const struct tcphdr* tcpHeader);
uint64_t getMicrosecondTs(uint32_t seconds, uint32_t microSeconds);
void printStats();
FlowTuple extractFlowTuple(const u_char* packet);
FlowTuple extractFlow(const struct ip* ipHeader, const struct tcphdr* tcpHeader);
void countUniqueFlows(const struct ip* ipHeader, const struct tcphdr* tcpHeader);
std::string toHexString(const std::string& str);
void printFlowTuple(const FlowTuple& flow);

int main(int argc, char *argv[]) {
    if (argc < 3){
        cout << "incorrect number of arguments. Need at least 2. (filenames, hash size)." << endl;
        return 0;
    }
    
    int numFiles = argc - 2;
    vector<char*> inputFiles;
    for (int i = 1; i <= numFiles; i++) {
        inputFiles.push_back(argv[i]);
        cout << "reading from file: " << argv[i] << endl;
    }

    int tableSize = atoi(argv[argc - 1]);
    stateInit(tableSize);

    vector<pcap_t*> descrs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open all PCAP files
    for (int i = 0; i < numFiles; i++) {
        pcap_t *descr = pcap_open_offline(inputFiles[i], errbuf);
        if (descr == NULL) {
            cerr << "pcap_open_offline() failed for " << inputFiles[i] << ": " << errbuf << endl;
            return 1;
        }
        descrs.push_back(descr);
    }

    printHeader();

    int active_pcap_count = descrs.size();
    while (active_pcap_count > 0) {
        for (size_t i = 0; i < descrs.size(); i++) {
            if (descrs[i] == nullptr) continue;

            struct pcap_pkthdr* header;
            const u_char* data;
            int res = pcap_next_ex(descrs[i], &header, &data);

            if (res == 1) { // Packet successfully read
                packetHandler(nullptr, header, data);
                
            } else if (res == -1) { // Error occurred
                cerr << "pcap_next_ex() failed: " << pcap_geterr(descrs[i]) << endl;
                return 1;
            } else if (res == -2) { // EOF reached
                pcap_close(descrs[i]);
                descrs[i] = nullptr;
                active_pcap_count--;
            }
        }
    }

    cout << "FINAL STATS:" << endl;
    printStats();

    return 0;
}

int main_onepcap(int argc, char *argv[]) {
  if (argc != 3){
    cout << "incorrect number of arguments. Need 2. (filename, hash size)." << endl;
    return 0;
  }
  char * inputFile = argv[1];
  cout << "reading from file: " << inputFile << endl;
  // Setup state. 
  int tableSize = atoi(argv[2]);
  stateInit(tableSize);

  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];
  // open capture file for offline processing
  descr = pcap_open_offline(inputFile, errbuf);
  printHeader();
  if (descr == NULL) {
      cerr << "pcap_open_live() failed: " << errbuf << endl;
      return 1;
  }
  // start packet processing loop, just like live capture
  if (pcap_loop(descr, 0, packetHandler, NULL) < 0) {
      cerr << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }
  cout << "FINAL STATS:" << endl;
  printStats();

  return 0;
}
  
void countUniqueFlows(const struct ip* ipHeader, const struct tcphdr* tcpHeader) {
    //FlowTuple flow = extractFlowTuple(packet);
    FlowTuple flow = extractFlow(ipHeader, tcpHeader);
    uniqueFlows.insert(flow);  // Automatically handles uniqueness
    //printFlowTuple(flow);
}

void stateInit(int tableSize){
  TABLELEN = tableSize;
  cout << "initializing hash tables to size: " << TABLELEN << endl;
  // Keys. 
  keyTable = new char*[tableSize];
  for (int i = 0; i< tableSize; i++){
    keyTable[i] = new char[KEYLEN];
  }
  // Counters. 
  byteCountTable = new uint32_t[tableSize];
  packetCountTable = new uint16_t[tableSize];

  // cout << "setting to attempt eviction once every " << pktsPerEvict << " packets " << endl;
  // packetsPerEvict = pktsPerEvict;
  return;  
}

void print_flowinfo(const struct ip* ipHeader, const struct tcphdr* tcpHeader) {
    // Extract the 5-tuple
    uint32_t srcIP = ipHeader->ip_src.s_addr;
    uint32_t dstIP = ipHeader->ip_dst.s_addr;
    uint16_t srcPort = ntohs(tcpHeader->source);
    uint16_t dstPort = ntohs(tcpHeader->dest);
    uint8_t protocol = ipHeader->ip_p;

    // Convert IP addresses to readable format
    struct in_addr srcAddr, dstAddr;
    srcAddr.s_addr = srcIP;
    dstAddr.s_addr = dstIP;

    // Print the 5-tuple
    std::cout << "Flow111: "
              << inet_ntoa(srcAddr) << ":" << srcPort << " -> "
              << inet_ntoa(dstAddr) << ":" << dstPort
              << " Protocol: " << static_cast<int>(protocol) << std::endl;
}
// The packet handler that implements the flow record generator. 
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  const struct ether_header* ethernetHeader;
  const struct ip* ipHeader;
  const struct tcphdr* tcpHeader;

  if (traceType == 0){
    ethernetHeader = (struct ether_header*)packet;
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
    }
  }
  else if (traceType == 1) {
    ipHeader = (struct ip*)(packet);
 
  }
  tcpHeader = (tcphdr*)((u_char*)ipHeader + sizeof(struct ip));

  // Call the function to print the flow info
  //print_flowinfo(ipHeader, tcpHeader);
  // Build metadata.
  Metadata md;  
  md.key = getKey(ipHeader, tcpHeader);
  md.ts = getMicrosecondTs(pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
  md.byteCount = pkthdr->len;
  md.hash = simpleHash(md.key.c_str(), KEYLEN, TABLELEN);
  if (startTs == 0){
    startTs = md.ts;
  }
  dur = md.ts - startTs;  

  // Update microflow tables.
  updateTables(md);

  // break after STOP_CT packets.
  dbg_packetCt++;
  countUniqueFlows(ipHeader, tcpHeader);
  /*if(dbg_packetCt > 3){
    exit(1);
  }*/
  #ifdef STOP_CT
    if (dbg_packetCt > STOP_CT){
      printStats();
      exit(1);
    }
  #endif
  #ifdef LOG_CT
    if (dbg_packetCt % LOG_CT == 0){
      printStats();
    }
  #endif
}

void updateTables(Metadata md){
  // increment packet counter. 
  packetSinceEvict++;
  // update key table.
  // read key at hash.
  char curKey[KEYLEN];
  memcpy(curKey, keyTable[md.hash], KEYLEN);
  bool evictedFlow = false;
  MicroflowRecord evictedMfr;
  // cout << "hash: " << md.hash << endl;
  // if the key is null, insert new entry. 
  if (memcmp(curKey, nullKey, KEYLEN) == 0){
    dbg_addFlowCt++;
    // cout << "inserting new. " << endl;
    memcpy(keyTable[md.hash], md.key.c_str(), KEYLEN);
    packetCountTable[md.hash] = 1;
    byteCountTable[md.hash] = md.byteCount;
  }
  else {
    // if key matches packet's key, update. 
    if (memcmp(curKey, md.key.c_str(), KEYLEN) == 0){
      packetCountTable[md.hash]++;
      byteCountTable[md.hash]+= md.byteCount;
    }
    // otherwise, it is a collision. Evict and then replace. 
    else {
      // Evict.
      evictedFlow = true;
      memcpy(evictedMfr.key, curKey, KEYLEN);
      evictedMfr.packetCount = packetCountTable[md.hash];
      evictedMfr.byteCount = byteCountTable[md.hash];
      // Replace.
      memcpy(keyTable[md.hash], md.key.c_str(), KEYLEN);
      packetCountTable[md.hash] = 1;
      byteCountTable[md.hash] = md.byteCount;

    }
  }
  // write microflow record if anything was evicted.
  if (evictedFlow){
    dumpMicroflowRecord(evictedMfr, true);    
  }
  return;
}


void printHeader(){
  cout << "packet counts, flow counts, avg packet length, trace time (ms), packets per microflow" << endl;
}

void printStats(){
    float packetsPerMicroflow = float(dbg_packetCt) / float(dbg_evictCt);
  //cout << dbg_packetCt << "," << dur/1000 << "," << packetsPerMicroflow << endl;
  cout << dbg_packetCt << "," << uniqueFlows.size() << "," << float(dbg_packetCt)/float(uniqueFlows.size()) << "," << dur/1000 << "," << packetsPerMicroflow << endl;
  //cout << "Number of unique flows: " << uniqueFlows.size() << endl;
  // fwrite(&mfr, 1, sizeof(mfr), stdout);
  return;
}


void dumpMicroflowRecord(MicroflowRecord mfr, bool collision){
  if (collision) dbg_collisionCt++;
  else dbg_removeFlowCt++;

  dbg_evictCt++;
  // Just write the microflow record to stdout. 
  // fwrite(&mfr, 1, sizeof(mfr), stdout);
  return;
}


std::string getKey(const struct ip* ipHeader, const struct tcphdr* tcpHeader){
  char keyBuf[KEYLEN];
  memcpy(&(keyBuf[0]), &ipHeader->ip_src, 4);
  memcpy(&(keyBuf[4]), &ipHeader->ip_dst, 4);
  memcpy(&(keyBuf[8]), &tcpHeader->source, 2);
  memcpy(&(keyBuf[10]), &tcpHeader->dest, 2);
  std::string key = string(keyBuf, KEYLEN);
  return key;
}

// Get 64 bit timestamp.
uint64_t getMicrosecondTs(uint32_t seconds, uint32_t microSeconds){
  uint64_t sec64, ms64;
  sec64 = (uint64_t) seconds;
  ms64 = (uint64_t) microSeconds;
  uint64_t ts = sec64 * 1000000 + ms64;
  return ts;
}
// A simple hashing function.
unsigned simpleHash(const char* s, int len, int maxHashVal)
{
    unsigned h = 0;
    for (int i=0; i<len; i++){
      h = h * 101 + (unsigned)s[i];
    }
    return h % maxHashVal;
}

FlowTuple extractFlow(const struct ip* ipHeader, const struct tcphdr* tcpHeader) {
    // Extract the source and destination IP addresses
    uint32_t srcIP = (ipHeader->ip_src.s_addr);  // Convert from network to host byte order
    uint32_t dstIP = (ipHeader->ip_dst.s_addr);  // Convert from network to host byte order

    // Extract the source and destination ports
    uint16_t srcPort = ntohs(tcpHeader->source);  // Convert from network to host byte order
    uint16_t dstPort = ntohs(tcpHeader->dest);    // Convert from network to host byte order

    // Extract the protocol
    uint8_t protocol = ipHeader->ip_p;

    // Return the flow as a tuple
    return std::make_tuple(srcIP, dstIP, srcPort, dstPort, protocol);
}
// Function to extract the flow 5-tuple from the packet
FlowTuple extractFlowTuple(const u_char* packet) {
    const struct ip* ipHeader = (struct ip*)(packet + 14);  // Skipping Ethernet header
    uint32_t srcIP = ipHeader->ip_src.s_addr;
    uint32_t dstIP = ipHeader->ip_dst.s_addr;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint8_t protocol = ipHeader->ip_p;

    if (protocol == IPPROTO_TCP) {
        const struct tcphdr* tcpHeader = (struct tcphdr*)(packet + 14 + ipHeader->ip_hl * 4);
        srcPort = ntohs(tcpHeader->source);
        dstPort = ntohs(tcpHeader->dest);
    } /*else if (protocol == IPPROTO_UDP) {
        const struct udphdr* udpHeader = (struct udphdr*)(packet + 14 + ipHeader->ip_hl * 4);
        srcPort = ntohs(udpHeader->source);
        dstPort = ntohs(udpHeader->dest);
    }*/

    return make_tuple(srcIP, dstIP, srcPort, dstPort, protocol);
}

// Function to convert binary data to a hexadecimal string
std::string toHexString(const std::string& str) {
    std::ostringstream hexStream;
    for (unsigned char c : str) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    }
    return hexStream.str();
}


void printFlowTuple(const FlowTuple& flow) {
    // Extract elements from the tuple
    uint32_t srcIP, dstIP;
    uint16_t srcPort, dstPort;
    uint8_t protocol;
    
    tie(srcIP, dstIP, srcPort, dstPort, protocol) = flow;
    
    // Convert IP addresses from network byte order to string
    struct in_addr srcAddr, dstAddr;
    srcAddr.s_addr = srcIP;
    dstAddr.s_addr = dstIP;
    
    // Convert ports from network byte order to host byte order
    srcPort = srcPort;
    dstPort = dstPort;
    
    // Print the flow tuple
    cout << "Flow: "
         << inet_ntoa(srcAddr) << ":" << srcPort << " -> "
         << inet_ntoa(dstAddr) << ":" << dstPort
         << " Protocol: " << static_cast<int>(protocol) << endl;
}