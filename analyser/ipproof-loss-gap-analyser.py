#!/usr/bin/env python

import struct
import sys
import os
import argparse
import time
import datetime
import logging
import dpkt
import binascii

from pprint import pprint
from subprocess import call

UDP = dpkt.udp.UDP

# script tests:
#./ipproof-loss-gap-analyser.py show  ./sending-host.pcap ./receiving-host.pcap
#./ipproof-loss-gap-analyser.py --tx-ether-src b8:ac:6f:43:04:4f show ./sending-host.pcap
#./ipproof-loss-gap-analyser.py --tx-ether-src 00:1b:21:29:a4:00 show ./foo.pcap
#
#./ipproof-loss-gap-analyser.py loss  ./sending-host.pcap ./receiving-host.pcap
#./ipproof-loss-gap-analyser.py --tx-ether-src b8:ac:6f:43:04:4f loss ./sending-host.pcap
#./ipproof-loss-gap-analyser.py --tx-ether-src 00:1b:21:29:a4:00 loss ./foo.pcap
# ./ipproof-loss-gap-analyser.py --tx-ether-src 00:90:b8:1c:10:62 loss ./foo.pcap

#./ipproof-loss-gap-analyser.py interframe-gap --stdio  ./sending-host.pcap ./receiving-host.pcap
#./ipproof-loss-gap-analyser.py --tx-ether-src 00:1b:21:29:a4:00 interframe-gap --stdio ./foo.pcap
#./ipproof-loss-gap-analyser.py interframe-gap --graph ./lol  ./sending-host.pcap ./receiving-host.pcap


class SkipProcessStepException(Exception): pass


class ExitCodes:
    EXIT_SUCCESS  = 0
    EXIT_ERROR    = 1
    EXIT_CMD_LINE = 2


class PcapParser:

    def __init__(self, pcap_file_path, pcap_filter):
        self.logger = logging.getLogger()
        self.pcap_file = False

        try:
            self.pcap_file = open(pcap_file_path)
        except IOError:
            self.logger.error("Cannot open pcap file: %s" % (pcap_file_path))
            sys.exit(ExitCodes.EXIT_ERROR)
        self.pc = dpkt.pcap.Reader(self.pcap_file)
        try:
            self.decode = {
                dpkt.pcap.DLT_LOOP:      dpkt.loopback.Loopback,
                dpkt.pcap.DLT_NULL:      dpkt.loopback.Loopback,
                dpkt.pcap.DLT_EN10MB:    dpkt.ethernet.Ethernet,
                dpkt.pcap.DLT_IEEE802:   dpkt.ethernet.Ethernet,
                dpkt.pcap.DLT_PPP:       dpkt.ppp.PPP,
                dpkt.pcap.DLT_LINUX_SLL: dpkt.sll.SLL
            }[self.pc.datalink()]
        except KeyError:
            self.logger.error("Packet link type not know (%d)! "
                              "Interprclass SkipProcessStepException(Exception): "
                              "passed at Ethernet now - but be carefull!" % (
                              self.pc.datalink()))
            self.decode = dpkt.ethernet.Ethernet


        if pcap_filter:
            self.pc.setfilter(pcap_filter)


    def __del__(self):
        if self.pcap_file:
            self.pcap_file.close()

    def register_callback(self, callback):
        self.callback = callback

    def packet_len_error(self, snaplen, packet_len):
        self.logger.critical("Captured data was too short (packet: %d, snaplen: %d)"
                            " - please recapture with snaplen of 0: infinity" %
                             (packet_len, snaplen))

    def run(self):
        try:
            for ts, pkt in self.pc:
                if self.pc.snaplen <= len(pkt):
                    self.packet_len_error(self.pc.snaplen, len(pkt))
                    sys.exit(1)
                packet = self.decode(pkt)
                dt = datetime.datetime.fromtimestamp(ts)
                self.callback(dt, packet)
        except SkipProcessStepException:
            self.logger.debug("skip processing step")


class Template:

    gnuplot_template = """
set terminal postscript eps enhanced color "Times" 25
set output "interframe-gap.eps"
set title "Interframe Gap Graph"

set style line 99 linetype 1 linecolor rgb "#999999" lw 2
set key right bottom
set key box linestyle 99
set key spacing 1.2

set grid xtics ytics mytics

set size 2
set size ratio 0.4

set format y "%.0f"

set ylabel "Interframe Gap [ms]"
set xlabel "Time [ms]"

set style line 1 lc rgb '#00004d' lt 1 lw 5

plot  \
    "interframe-gap.data" using 1:2 title "Seq" with linespoints ls 1

"""


    makefile_template = """
GNUPLOT_FILES = $(wildcard *.gpi)
PNG_OBJ = $(patsubst %.gpi,%.png,  $(GNUPLOT_FILES))
PDF_OBJ = $(patsubst %.gpi,%.pdf,  $(GNUPLOT_FILES))

all: $(PDF_OBJ)
png: $(PNG_OBJ)

%.eps: %.gpi *.data
	@ echo "compillation of "$<
	@gnuplot $<

%.pdf: %.eps
	@echo "conversion in pdf format"
	@epstopdf --outfile=$*.pdf $<
	@echo "end"

%.png: %.pdf
	@echo "conversion in png format"
	@convert -density 300 $< $*.png 
	@echo "end"

preview: all
	for i in $$(ls *.pdf); do xpdf -fullscreen $$i ; done

clean:
	@echo "cleaning ..."
	@rm -rf *.eps *.pdf core

distclean: clean
	@echo "distclean"
	@rm -rf *.data
"""


class LossMod:

    def __init__(self):
        pass

class FlowDb:

    def __init__(self):
        self.db = dict()
        self.sent_packet_id = dict()
        self.eth_src_addr = ""

    def packet_flow_id(self, packet):
        payload = packet.data.data.data
        s = struct.Struct('>H')        

        if ord(payload[0]) & 0b000100000:        #extended header
            flow_id = int(s.unpack(payload[2:4])[0])                
        else:                                    #normal header   
            flow_id = ord(payload[1])

        return flow_id


    def get_packet_data(self, packet):
        payload = packet.data.data.data
        s = struct.Struct('>H')

        if ord(payload[0]) & 0b000100000:
            #extended header
            flow_id = int(s.unpack(payload[2:4])[0])
            seq_num = int(s.unpack(payload[4:6])[0])<<16
            seq_num += int(s.unpack(payload[6:8])[0])
            data_len = int(s.unpack(payload[8:10])[0])<<16
            data_len += int(s.unpack(payload[10:12])[0])        
        else:
            #normal header
            flow_id = ord(payload[1])
            seq_num = int(s.unpack(payload[2:4])[0])
            data_len = int(s.unpack(payload[4:6])[0])<<16
            data_len += int(s.unpack(payload[6:8])[0])
  
        return flow_id, seq_num, data_len

    def print_packet_data(self, ts,  packet): 
        print self.get_packet_data(packet)

    def add_packet_left(self, ts, packet):
        # left subtable, SENT PACKETS (2 files)
        flow_id, seq_num, data_len = self.get_packet_data(packet)

        if not self.db.has_key(flow_id):
            #first entry for this flow, create a data table
            self.db[flow_id] = dict()
            self.db[flow_id]["start-time"] = ts
            self.db[flow_id]["data"] = []
            self.sent_packet_id[flow_id]=0

        self.db[flow_id]["data"].append([])
        self.db[flow_id]["data"][-1].append({ "ts":ts, "seq":seq_num, "length":data_len })
        self.db[flow_id]["data"][-1].append({})

    def add_packet_right(self, ts, packet):
        # right subtable, RECEIVED PACKETS (2 files)
        flow_id, seq_num, data_len = self.get_packet_data(packet)

        if not self.db.has_key(flow_id):
            print "Received notsent packets. RCVD_Flow_ID(",flow_id,") does not match SND_Flow_ID"
            raise Exception("Received notsent packets. RCVD_Flow_ID does not match SND_Flow_ID" )
    
        while  self.db[flow_id]["data"][self.sent_packet_id[flow_id]][0]["seq"] != seq_num:
            self.sent_packet_id[flow_id] += 1
            if self.sent_packet_id[flow_id] > len(self.db[flow_id]["data"]):
                print 'reordering occured'
                raise Exception('reordering occured' )      

        self.db[flow_id]["data"][self.sent_packet_id[flow_id]][1]={ "ts":ts, "seq":seq_num, "length":data_len }
    

    def add_packet(self, ts, packet):
        # single file processing
        flow_id, seq_num, data_len = self.get_packet_data(packet)
        
        if binascii.hexlify(packet.src).startswith(self.eth_src_addr):
            # outgoingpacket
            if not self.db.has_key(flow_id):
                # first entry for this flow, create a data table
                self.db[flow_id] = dict()
                self.db[flow_id]["start-time"] = ts
                self.db[flow_id]["data"] = []
                self.sent_packet_id[flow_id]=0    
            
            self.db[flow_id]["data"].append([])
            self.db[flow_id]["data"][-1].append({ "ts":ts, "seq":seq_num, "length":data_len })
            self.db[flow_id]["data"][-1].append({})
    
        else:
            #incomingpacket
            if not self.db.has_key(flow_id):
                print "Received notsent packets. RCVD_Flow_ID(",flow_id,") does not match SND_Flow_ID"
                raise Exception("Received notsent packets. RCVD_Flow_ID does not match SND_Flow_ID" )
                
 
            while  self.db[flow_id]["data"][self.sent_packet_id[flow_id]][0]["seq"] != seq_num:
                self.sent_packet_id[flow_id] += 1
                if self.sent_packet_id[flow_id] > len(self.db[flow_id]["data"]):
                    print 'reordering occured'
                    raise Exception('reordering occured' )

            self.db[flow_id]["data"][self.sent_packet_id[flow_id]][1]={ "ts":ts, "seq":seq_num, "length":data_len }



class PcapIpproofFrameAnalyser:

    def __init__(self):
        self.captcp_starttime = datetime.datetime.today()
        self.pcap_filter = None
        self.pcap_file_path = False

        self.arg_parser = argparse.ArgumentParser()
        self.arg_list = ""
        self.flow_db = FlowDb()

    def check_args(self):
        if (not self.arg_list.ethsrc) and (not self.arg_list.file2):
            raise Exception('tx-ether-src needs to be specified for one file pcap input')
        #elif:
                 

    def parse_args(self):
        self.arg_parser.add_argument('--tx-ether-src',
                                     action='store', dest='ethsrc',
                                    help='ethernet source MAC adress, essential with 1 pcap file input, format ff:ff:ff:ff:ff:ff')
        self.arg_parser.add_argument('--dport-filter', action='store', dest='dport', type=int)
        self.arg_parser.add_argument('--sport-filter', action='store', dest='sport', type=int)   
        self.arg_parser.add_argument('module', action='store', help='show | loss | interframe-gap')    
        self.arg_parser.add_argument('--stdio', action='store_true', default=False,
                                    help='applicabe only for interframe-gap module')
        self.arg_parser.add_argument('--graph', action='store', dest='grph_path',
                                    help='applicabe only for interframe-gap module to specify output directory for graph')
        self.arg_parser.add_argument('file1', action='store', help='pcap file (trasmitter or both TX & RX)')
        self.arg_parser.add_argument('file2', action='store', nargs='?', help='pcap file (receiver)')
            
        self.arg_list=self.arg_parser.parse_args()
        self.check_args()
             
    def make_flow_db(self):
        if bool(self.arg_list.file1) and bool(self.arg_list.file2):                
            self.make_flow_db_2files()
        elif bool(self.arg_list.file1):
            self.make_flow_db_file()

    def make_flow_db_2files(self):
        pcap_rx_parser = PcapParser(self.arg_list.file1, None)
        pcap_tx_parser = PcapParser(self.arg_list.file2, None)
        pcap_rx_parser.register_callback(self.flow_db.add_packet_left)
        pcap_tx_parser.register_callback(self.flow_db.add_packet_right)
        pcap_rx_parser.run()
        pcap_tx_parser.run()
        
    def make_flow_db_file(self):
        self.flow_db.eth_src_addr = self.arg_list.ethsrc.replace(':','')
        pcap_parser = PcapParser(self.arg_list.file1, None)
        pcap_parser.register_callback(self.flow_db.add_packet)
        pcap_parser.run()   
                    
    def print_packet_flow_id(self, ts, packet):
        self.flow_db.print_packet_data(packet)

    def run(self):
        self.parse_args()
        self.make_flow_db()
        if self.arg_list.module == 'show':
            self.run_show()
        elif self.arg_list.module == 'loss':
            self.run_loss()
        elif self.arg_list.module == 'interframe-gap':
            self.run_interframe_gap()

    def run_interframe_gap(self):
        if self.arg_list.stdio:
            for fid in self.flow_db.db.keys():
                sys.stdout.write("Analysed Flow: %d\n\n" % (fid) )
                for p in self.flow_db.db[fid]["data"]:              
                    if bool(p[1]):
                        # packet received
                        delta2 = p[1]["ts"] - p[0]["ts"]
                        sys.stdout.write("\t%3.3f" %((float(delta2.microseconds))/1000) )
                    else:
                        # packet lost
                        sys.stdout.write("\tPACKET LOST")                

                    sys.stdout.write("\n")
        
        if self.arg_list.grph_path:
            self.init_interframegap_graph()


    def init_interframegap_graph(self):
        if not os.path.exists(self.arg_list.grph_path):        
            os.mkdir(self.arg_list.grph_path)
        foo = Template.makefile_template
        fp = open(self.arg_list.grph_path + "/Makefile", "w")
        fp.write(foo)
        fp.close()
        foo = Template.gnuplot_template
        fp = open(self.arg_list.grph_path + "/interframe-gap.gpi", "w")
        fp.write(foo)
        fp.close()
        fp = open(self.arg_list.grph_path + "/interframe-gap.data", "w")
        for fid in self.flow_db.db.keys():
            start_time =   self.flow_db.db[fid]["start-time"]
            for p in self.flow_db.db[fid]["data"]:              
                if bool(p[1]):
                    # packet received
                    delta1 = p[0]["ts"] - start_time
                    fp.write("%3.3f" %((float(delta1.microseconds))/1000) )
                    delta2 = p[1]["ts"] - p[0]["ts"]
                    fp.write("\t%3.3f" %((float(delta2.microseconds))/1000) )
                else:
                    # packet lost
                    fp.write("\tPACKET LOST")                
                    pass
                
                fp.write("\n")        
        fp.close()

        sys.stdout.write("Gnuplot environment (including data file) generated\n")
        sys.stdout.write("Time to generate PDF: $(cd %s;make pdf)\n" % (self.arg_list.grph_path))

        
    def run_loss(self):
        if True:
            for fid in self.flow_db.db.keys():
                sys.stdout.write("\n\nAnalyzed Flow: %d\n" % (fid) )

                sys.stdout.write("Loss - NoLoss - Characteristic (0: no-loss, 1: loss):\n")
                #sys.stdout.write("-----------------------------------------------------\n")
                num_of_symbols=0
                loss_string = ""
                for p in self.flow_db.db[fid]["data"]:      
                    if p[0] and p[1]:
                        sys.stdout.write("0")
                        loss_string += "0"
                    else:
                        sys.stdout.write("1")
                        loss_string += "1"
                    num_of_symbols += 1

                    if not(num_of_symbols % 70):
                        sys.stdout.write("\n")            
                
                sys.stdout.write("\n")  
                self.get_loss_model(loss_string)    
                               

    
    def run_show(self):
        for fid in self.flow_db.db.keys():
            sys.stdout.write("Flow: %d\n" % (fid) )
            start_time =   self.flow_db.db[fid]["start-time"]
            for p in self.flow_db.db[fid]["data"]:              
                delta1 = p[0]["ts"] - start_time           
                sys.stdout.write("\t%3.3f" % ((float(delta1.microseconds))/1000) )
                sys.stdout.write(" [seq: %d, byte: %d] -" %  (p[0]["seq"], p[0]["length"]) )
                
                if bool(p[1]):
                    # packet received
                    delta2 = p[1]["ts"] - p[0]["ts"]
                    sys.stdout.write("-> %3.3f" % ((float(delta2.microseconds))/1000) )
                    sys.stdout.write(" [seq: %d, byte: %d]" %  (p[1]["seq"], p[1]["length"]) )
                else:
                    # packet lost
                    sys.stdout.write("->  PACKET LOST")                

                sys.stdout.write("\n")
    
    def get_loss_model(self, loss_string):
        dat=loss_string
        print "P_loss: %.3f %%" % (100.0*loss_string.count('1')/len(loss_string),)
        err_num = 0
        p_num=len(dat)
        in_burst = 0
        burst_num = 0
        burst_sum = 0

        for i, c in enumerate(dat):
            if c == '1':
                err_num  += 1
                if in_burst == 1 :
                    burst_sum += 1
                else :
                    in_burst = 1
                    burst_num += 1
                
            elif c == '0':
                in_burst = 0
          
 
        Perr = float(err_num)/p_num
        if burst_num > 0 :      
            AvgBurstLen = float(burst_sum)/burst_num
        else:
            AvgBurstLen = 0


        p31 = 1/float(1+AvgBurstLen)
        if Perr != 1:
             p13 = p31 * Perr / (1 - Perr)
        else:
            p13 = 1
            p31 = 0

        sys.stdout.write("\n4 State Markov Chain Transition Probability:\n")
        #sys.stdout.write("--------------------------------------------\n")
        sys.stdout.write("p13 = %.3lf %%\n" % (100 * p13) )
        sys.stdout.write("p31 = %.3lf %%\n" % (100 * p31) )


if __name__ == "__main__":
    try:
        pifa = PcapIpproofFrameAnalyser()
        sys.exit(pifa.run())
    except KeyboardInterrupt:
        sys.stderr.write("SIGINT received, exiting\n")
