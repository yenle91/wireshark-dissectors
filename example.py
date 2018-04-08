'''
Created on Apr 7, 2018

@author: admin
'''
import pyshark

class SipProtocol(object):
    '''
    hdr = {
        '@': '', 'To': None, 'From': None, 'Call-ID': None, 'CSeq': None, 'Contact': None, 'Via': None, 'Content-Length': None, 'Content-Type': None
    }
    body = {
        'version': '0',
        'owner': None,
        'session_name': '',
        'connection_info': None,
        'time': None,
        'media': {'@': '', 'type': '', 'port': '', 'proto': '','format': [] },
        'media_attr': []
    }
    '''
    def __init__(self, sipEntries):
        self.hdr = {}
        self.hdr['@']        = sipEntries.get('sip.msg_hdr')
        self.hdr['From']     = {'@': sipEntries.get('sip.From'), 'addr': sipEntries.get('sip.from.addr'), 'tag': sipEntries.get('sip.from.tag')}
        self.hdr['To']       = {'@': sipEntries.get('sip.To'), 'addr': sipEntries.get('sip.to.addr'), 'tag': sipEntries.get('sip.to.tag')}
        self.hdr['Call-ID']  = sipEntries.get('sip.Call-ID')
        self.hdr['CSeq']     = {'@': sipEntries.get('sip.CSeq'), 'method': sipEntries.get('sip.CSeq.method'), 'seq': sipEntries.get('sip.CSeq.seq')}
        self.hdr['Contact']  = {'@': sipEntries.get('sip.Contact'), 'host': sipEntries.get('sip.contact.host'), 'port': sipEntries.get('sip.contact.port')}
        self.hdr['Via']      = {'@': sipEntries.get('sip.Via'), 'address': sipEntries.get('sip.Via.sent-by.address'), 'branch': sipEntries.get('sip.Via.branch')}
        self.hdr['Content-Length'] = sipEntries.get('sip.Content-Length')
        self.hdr['Content-Type'] = sipEntries.get('sip.Content-Type') 
        
        if self.hdr['Content-Length'] != None:
            self.body = {}
            self.body['version']            = sipEntries.get('sdp.version')
            self.body['owner']              = sipEntries.get('sdp.owner')
            self.body['session_name']       = sipEntries.get('sdp.session_name')
            self.body['connection_info']    = sipEntries.get('sdp.connection_info')
            self.body['time']               = sipEntries.get('sdp.time')
        
class SipRequest(SipProtocol):
    #reqLine = {
    #    '@': '', 'method': None, 'uri': None
    #}
    def __init__(self, sipEntries):
        super(SipRequest, self).__init__(sipEntries)
        self.reqLine = {}
        self.reqLine['@'] = sipEntries.get('sip.Request-Line')
        self.reqLine['method'] = sipEntries.get('sip.Method')
        self.reqLine['uri'] = sipEntries.get('sip.r-uri')

class SipResponse(SipProtocol):
    #statusLine = {'@':'', 'statusCode':''}
    def __init__(self, sipEntries):
        super(SipResponse, self).__init__(sipEntries)
        self.statusLine = {}
        self.statusLine['@'] = sipEntries.get('sip.Status-Line') 
        self.statusLine['statusCode'] = sipEntries.get('sip.Status-Code')    
        
# Open saved trace file
cap = pyshark.FileCapture('traces/SIP_CALL_RTP_G711.pcap')

def getSipFlow():
    capFile = pyshark.FileCapture('traces/SIP_CALL_RTP_G711.pcap')
    flow = []
    for pkt in capFile:
        '''TODO: Add log number of sip message
        '''
        if (pkt.highest_layer == 'SIP'):
            method = None
            method = pkt.sip.get('sip.Method')            
            if(method != None):           
                flow.append(SipRequest(pkt.sip._all_fields))
            else:
                flow.append(SipResponse(pkt.sip._all_fields))
    return flow
    
def flowFilterByProtocol(protocol):
    flow = []
    for pkt in cap:
        if (pkt.highest_layer == protocol):
            flow.append(pkt)
    return flow

def flowSipFilterByNode(src = '', dst = ''):
    sipFlow = []
    for pkt in cap:
        if (pkt.ip.src == src & pkt.ip.dst == dst & pkt.highest_layer == 'SIP'):
            if (pkt.sip.Method != None):            
                sipFlow.append(SipRequest(pkt.sip._all_fields))
            else:
                sipFlow.append(SipResponse(pkt.sip._all_fields))
    return sipFlow        

def getSipDialog(call_ID = '', from_tag = '', to_tag = '', sipFlow = getSipFlow()):
    dialog = []
    #sipFlow = getSipFlow()
    for msg in sipFlow:
        if ((msg.hdr['Call-ID'] == call_ID) and (msg.hdr['From']['tag'] == from_tag)) or ((msg.hdr['Call-ID'] == call_ID) and msg.hdr['To']['tag'] == to_tag):
            dialog.append(msg)
    return dialog 


#sipFlow = getSipFlow()
dialog = getSipDialog("12013223@200.57.7.195", "GR52RWG346-34", "298852044")
        
test = None

    

