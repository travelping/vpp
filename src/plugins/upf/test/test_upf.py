from datetime import datetime
import uuid
import framework
from random import getrandbits
from scapy.contrib.pfcp import CauseValues, IE_ApplyAction, IE_Cause, \
    IE_CreateFAR, IE_CreatePDR, IE_CreateURR, IE_DestinationInterface, \
    IE_DurationMeasurement, IE_EndTime, IE_EnterpriseSpecific, IE_FAR_Id, \
    IE_ForwardingParameters, IE_FSEID, IE_MeasurementMethod, \
    IE_NetworkInstance, IE_NodeId, IE_PDI, IE_PDR_Id, IE_Precedence, \
    IE_QueryURR, IE_RecoveryTimeStamp, IE_RedirectInformation, IE_ReportType, \
    IE_ReportingTriggers, IE_SDF_Filter, IE_SourceInterface, IE_StartTime, \
    IE_TimeQuota, IE_UE_IP_Address, IE_URR_Id, IE_UR_SEQN, \
    IE_UsageReportTrigger, IE_VolumeMeasurement, IE_ApplicationId, PFCP, \
    PFCPAssociationSetupRequest, PFCPAssociationSetupResponse, \
    PFCPHeartbeatRequest, PFCPHeartbeatResponse, PFCPSessionDeletionRequest, \
    PFCPSessionDeletionResponse, PFCPSessionEstablishmentRequest, \
    PFCPSessionEstablishmentResponse, PFCPSessionModificationRequest, \
    PFCPSessionModificationResponse, PFCPSessionReportRequest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_ServerName, \
    ServerName, TLS_Ext_SupportedPointFormat, TLS_Ext_SupportedGroups, \
    TLS_Ext_SignatureAlgorithms, TLS_Ext_ALPN, ProtocolName
from scapy.packet import Raw


def seid():
    return uuid.uuid4().int & (1 << 64) - 1


def filter_ies(ies):
    return [ie for ie in ies if ie]


DROP_IP = "192.0.2.99"
REDIR_IP = "192.0.2.100"
REDIR_TARGET_IP = "198.51.100.42"
APP_RULE_IP = "192.0.2.101"
NON_APP_RULE_IP = "192.0.9.201"
NON_APP_RULE_IP_2 = "192.0.9.202"
NON_APP_RULE_IP_3 = "192.0.9.203"
EXTRA_SDF_IP = "192.0.9.204"


class TestUPF(framework.VppTestCase):
    """Test UPF"""

    @classmethod
    def setUpClass(cls):
        cls.ts = int((datetime.now() - datetime(1900, 1, 1)).total_seconds())
        super(TestUPF, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(3))
            cls.interfaces = list(cls.pg_interfaces)

            cls.vapi.cli("ip table add 1")
            cls.vapi.cli("ip table add 2")
            # separate assignments are easier to understand for some
            # tools like elpy than this:
            # cls.if_cp, cls.if_access, cls.if_sgi = cls.interfaces
            cls.if_cp = cls.interfaces[0]
            cls.if_access = cls.interfaces[1]
            cls.if_sgi = cls.interfaces[2]
            for n, i in enumerate(cls.interfaces):
                i.admin_up()
                cls.vapi.cli("set interface ip table %s %d" % (i.name, n))
                i.config_ip4()
                i.resolve_arp()
            for cmd in cls.upf_setup_cmds():
                cls.vapi.cli(cmd)
        except Exception:
            super(TestUPF, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestUPF, cls).tearDownClass()

    @classmethod
    def upf_setup_cmds(cls):
        return [
            "upf nwi name cp vrf 0",
            "upf nwi name access vrf 1",
            "upf nwi name sgi vrf 2",
            "upf pfcp endpoint ip %s vrf 0" % cls.if_cp.local_ip4,
            "upf gtpu endpoint ip %s nwi cp teid 0x80000000/2" %
            cls.if_cp.local_ip4,
            "upf tdf ul table vrf 1 ip4 table-id 1001",
            "upf tdf ul enable ip4 %s" % cls.if_access.name,
            "ip route add 0.0.0.0/0 table 2 via %s %s" %
            (cls.if_sgi.remote_ip4, cls.if_sgi.name),
            "create upf application name TST",
            "upf application TST rule 3000 add l7 regex " +
            r"^https?://(.*\\.)*(example)\\.com/",
            "upf application TST rule 3001 add ipfilter " +
            "permit out ip from %s to assigned" % APP_RULE_IP,
        ]

    def setUp(self):
        super(TestUPF, self).setUp()
        self.seq = 1

    def tearDown(self):
        super(TestUPF, self).tearDown()

    def test_upf(self):
        try:
            self.associate()
            self.heartbeat()
            self.verify_no_forwarding()
            self.establish_session()
            self.verify_forwarding()
            self.verify_drop()
            # FIXME: the IP redirect is currently also handled by the proxy
            # self.verify_redirect()
            self.delete_session()
            self.verify_no_forwarding()
        finally:
            self.vapi.cli("show error")

    def test_reporting(self):
        try:
            self.associate()
            self.heartbeat()
            self.establish_reporting_session(report_app=False)
            self.verify_reporting()
            self.verify_session_modification()
            self.delete_session()
        finally:
            self.vapi.cli("show error")

    def test_app_reporting(self):
        try:
            self.associate()
            self.heartbeat()
            self.establish_reporting_session(report_app=True)
            self.verify_app_reporting()
            self.vapi.cli("show upf flows")
            self.delete_session()
        finally:
            self.vapi.cli("show error")

    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show upf flows"))
        self.logger.info(self.vapi.cli("show hardware"))

    def chat(self, pkt, expectedResponse, seid=None):
        self.logger.info("REQ: %r" % pkt)
        self.if_cp.add_stream(
            Ether(src=self.if_cp.remote_mac, dst=self.if_cp.local_mac) /
            IP(src=self.if_cp.remote_ip4, dst=self.if_cp.local_ip4) /
            UDP(sport=8805, dport=8805) /
            PFCP(
                version=1, seq=self.seq,
                S=0 if seid is None else 1,
                seid=0 if seid is None else seid) /
            pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        resp = self.if_cp.get_capture(1)[0][PFCP]
        self.logger.info("RESP: %r" % resp)
        self.assertEqual(resp.seq, self.seq)
        self.seq += 1
        return resp[expectedResponse]

    def associate(self):
        resp = self.chat(PFCPAssociationSetupRequest(IE_list=[
            IE_RecoveryTimeStamp(timestamp=self.ts),
            IE_NodeId(id_type="FQDN", id="ergw")
            ]), PFCPAssociationSetupResponse)
        self.assertEqual(CauseValues[resp[IE_Cause].cause], "Request accepted")
        self.assertIn(b"vpp", resp[IE_EnterpriseSpecific].data)

    def heartbeat(self):
        resp = self.chat(PFCPHeartbeatRequest(IE_list=[
            IE_RecoveryTimeStamp(timestamp=self.ts)
            ]), PFCPHeartbeatResponse)
        self.assertIn(IE_RecoveryTimeStamp, resp)

    def establish_session(self):
        cp_ip = self.if_cp.remote_ip4
        ue_ip = self.if_access.remote_ip4
        self.cur_seid = seid()
        resp = self.chat(PFCPSessionEstablishmentRequest(IE_list=[
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(id=1),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="SGi-LAN/N6-LAN"),
                    IE_NetworkInstance(instance="sgi")
                ])
            ]),
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(id=2),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="Access"),
                    IE_NetworkInstance(instance="access")
                ])
            ]),
            # FIXME: this is not handled properly :(
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(id=3),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="SGi-LAN/N6-LAN"),
                    IE_NetworkInstance(instance="sgi"),
                    IE_RedirectInformation(
                        type="IPv4 address",
                        address=REDIR_TARGET_IP)
                ])
            ]),
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(DROP=1),
                IE_FAR_Id(id=4),
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=1),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(instance="access"),
                    IE_SDF_Filter(
                        FD=1,
                        flow_description="permit out ip from any to assigned"),
                    IE_SourceInterface(interface="Access"),
                    IE_UE_IP_Address(ipv4=ue_ip, V4=1)
                ]),
                IE_PDR_Id(id=1),
                IE_Precedence(precedence=200),
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=2),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(instance="sgi"),
                    IE_SDF_Filter(
                        FD=1,
                        flow_description="permit out ip from any to assigned"),
                    IE_SourceInterface(interface="SGi-LAN/N6-LAN"),
                    IE_UE_IP_Address(ipv4=ue_ip, SD=1, V4=1)
                ]),
                IE_PDR_Id(id=2),
                IE_Precedence(precedence=200),
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=3),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(instance="access"),
                    IE_SDF_Filter(
                        FD=1,
                        flow_description="permit out ip from %s to assigned" %
                        REDIR_IP),
                    IE_SourceInterface(interface="Access"),
                    IE_UE_IP_Address(ipv4=ue_ip, V4=1)
                ]),
                IE_PDR_Id(id=3),
                IE_Precedence(precedence=100),
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=4),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(instance="access"),
                    IE_SDF_Filter(
                        FD=1,
                        flow_description="permit out ip from %s to assigned" %
                        DROP_IP),
                    IE_SourceInterface(interface="Access"),
                    IE_UE_IP_Address(ipv4=ue_ip, V4=1)
                ]),
                IE_PDR_Id(id=4),
                IE_Precedence(precedence=100),
            ]),
            IE_FSEID(ipv4=cp_ip, v4=1, seid=self.cur_seid),
            IE_NodeId(id_type=2, id="ergw")
        ]), PFCPSessionEstablishmentResponse, seid=self.cur_seid)
        self.assertEqual(CauseValues[resp[IE_Cause].cause], "Request accepted")
        self.assertEqual(resp[IE_FSEID].ipv4, self.if_cp.local_ip4)
        self.assertEqual(resp[IE_FSEID].seid, self.cur_seid)

    def establish_reporting_session(self, report_app=False):
        cp_ip = self.if_cp.remote_ip4
        ue_ip = self.if_access.remote_ip4
        self.cur_seid = seid()
        resp = self.chat(PFCPSessionEstablishmentRequest(IE_list=filter_ies([
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(id=1),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="SGi-LAN/N6-LAN"),
                    IE_NetworkInstance(instance="sgi")
                ])
            ]),
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(id=2),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="Access"),
                    IE_NetworkInstance(instance="access")
                ])
            ]),
            IE_CreateURR(IE_list=[
                IE_MeasurementMethod(EVENT=1, VOLUM=1, DURAT=1),
                IE_ReportingTriggers(start_of_traffic=1),
                IE_TimeQuota(quota=60),
                IE_URR_Id(id=1)
            ]) if not report_app else None,
            IE_CreatePDR(IE_list=filter_ies([
                IE_FAR_Id(id=1),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(instance="access"),
                    IE_SDF_Filter(
                        FD=1,
                        flow_description="permit out ip from any to assigned"),
                    IE_SourceInterface(interface="Access"),
                    IE_UE_IP_Address(ipv4=ue_ip, V4=1)
                ]),
                IE_PDR_Id(id=1),
                IE_Precedence(precedence=200),
                IE_URR_Id(id=1) if not report_app else None
            ])),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=2),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(instance="sgi"),
                    IE_SDF_Filter(
                        FD=1,
                        flow_description="permit out ip from any to assigned"),
                    IE_SourceInterface(interface="SGi-LAN/N6-LAN"),
                    IE_UE_IP_Address(ipv4=ue_ip, SD=1, V4=1)
                ]),
                IE_PDR_Id(id=2),
                IE_Precedence(precedence=200),
            ]),
            IE_CreateURR(IE_list=[
                IE_MeasurementMethod(VOLUM=1, DURAT=1),
                IE_ReportingTriggers(),
                IE_TimeQuota(quota=60),
                IE_URR_Id(id=2)
            ]) if report_app else None,
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=1),
                IE_PDI(IE_list=[
                    IE_SDF_Filter(
                        FD=1,
                        flow_description="permit out ip from %s to assigned" % EXTRA_SDF_IP),
                    IE_ApplicationId(id="TST"),
                    IE_NetworkInstance(instance="access"),
                    IE_SourceInterface(interface="Access"),
                    IE_UE_IP_Address(ipv4=ue_ip, V4=1)
                ]),
                IE_PDR_Id(id=3),
                IE_Precedence(precedence=100),
                IE_URR_Id(id=2)
            ]) if report_app else None,
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(id=2),
                IE_PDI(IE_list=[
                    IE_SDF_Filter(
                        FD=1,
                        flow_description="permit out ip from %s to assigned" % EXTRA_SDF_IP),
                    IE_ApplicationId(id="TST"),
                    IE_NetworkInstance(instance="sgi"),
                    IE_SourceInterface(interface="SGi-LAN/N6-LAN"),
                    IE_UE_IP_Address(ipv4=ue_ip, SD=1, V4=1)
                ]),
                IE_PDR_Id(id=4),
                # FIXME: likely a bug in 20.01 branch: PDR for DL
                # traffic must have lower precedence
                IE_Precedence(precedence=10),
                IE_URR_Id(id=2)
            ]) if report_app else None,
            IE_FSEID(ipv4=cp_ip, v4=1, seid=self.cur_seid),
            IE_NodeId(id_type=2, id="ergw")
        ])), PFCPSessionEstablishmentResponse, seid=self.cur_seid)
        self.assertEqual(CauseValues[resp[IE_Cause].cause], "Request accepted")
        self.assertEqual(resp[IE_FSEID].ipv4, self.if_cp.local_ip4)
        self.assertEqual(resp[IE_FSEID].seid, self.cur_seid)

    def delete_session(self):
        cp_ip = self.if_cp.remote_ip4
        resp = self.chat(PFCPSessionDeletionRequest(IE_list=[
            IE_FSEID(ipv4=cp_ip, v4=1, seid=self.cur_seid),
            IE_NodeId(id_type=2, id="ergw")
        ]), PFCPSessionDeletionResponse, seid=self.cur_seid)
        self.assertEqual(CauseValues[resp[IE_Cause].cause], "Request accepted")

    def send_from_access_to_sgi(self, payload=None, l4proto=UDP, ue_port=12345, remote_port=23456, remote_ip=None, **kwargs):
        if remote_ip is None:
            remote_ip = self.if_sgi.remote_ip4
        to_send = Ether(src=self.if_access.remote_mac, dst=self.if_access.local_mac) / \
            IP(src=self.if_access.remote_ip4, dst=remote_ip) / \
            l4proto(sport=ue_port, dport=remote_port, **kwargs)
        if payload is not None:
            to_send /= Raw(payload)
        self.if_access.add_stream(to_send)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        return len(to_send[IP])

    def assert_packet_sent_to_sgi(self, payload=None, l4proto=UDP, ue_port=12345, remote_port=23456, remote_ip=None):
        if remote_ip is None:
            remote_ip = self.if_sgi.remote_ip4
        pkt = self.if_sgi.get_capture(1)[0]
        self.assertEqual(pkt[IP].src, self.if_access.remote_ip4)
        self.assertEqual(pkt[IP].dst, remote_ip)
        self.assertEqual(pkt[l4proto].sport, ue_port)
        self.assertEqual(pkt[l4proto].dport, remote_port)
        if payload is not None:
            self.assertEqual(pkt[Raw].load, payload)

    def assert_packet_not_sent_to_sgi(self):
        self.if_sgi.assert_nothing_captured()

    def send_from_sgi_to_access(self, payload=None, l4proto=UDP, ue_port=12345, remote_port=23456, remote_ip=None, **kwargs):
        if remote_ip is None:
            remote_ip = self.if_sgi.remote_ip4
        to_send = Ether(src=self.if_sgi.remote_mac, dst=self.if_sgi.local_mac) / \
            IP(src=remote_ip, dst=self.if_access.remote_ip4) / \
            l4proto(sport=remote_port, dport=ue_port, **kwargs)
        if payload is not None:
            if isinstance(payload, bytes):
                payload = Raw(payload)
            to_send /= payload
        self.if_sgi.add_stream(to_send)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        return len(to_send[IP])

    def assert_packet_sent_to_access(self, payload=None, l4proto=UDP, ue_port=12345, remote_port=23456, remote_ip=None):
        if remote_ip is None:
            remote_ip = self.if_sgi.remote_ip4
        pkt = self.if_access.get_capture(1)[0]
        self.assertEqual(pkt[IP].src, remote_ip)
        self.assertEqual(pkt[IP].dst, self.if_access.remote_ip4)
        self.assertEqual(pkt[l4proto].sport, remote_port)
        self.assertEqual(pkt[l4proto].dport, ue_port)
        if payload is not None:
            self.assertEqual(pkt[Raw].load, payload)

    def assert_packet_not_sent_to_access(self):
        self.if_access.assert_nothing_captured()

    def verify_no_forwarding(self):
        # Access -> SGi
        self.send_from_access_to_sgi(b"42")
        self.assert_packet_not_sent_to_sgi()
        # SGi -> Access
        self.send_from_sgi_to_access(b"42")
        self.assert_packet_not_sent_to_access()

    def verify_forwarding(self):
        # Access -> SGi
        self.send_from_access_to_sgi(b"42")
        self.assert_packet_sent_to_sgi(b"42")
        # SGi -> Access
        self.send_from_sgi_to_access(b"4242")
        self.assert_packet_sent_to_access(b"4242")

    def verify_drop(self):
        # Access -> SGi
        self.send_from_access_to_sgi(b"42", remote_ip=DROP_IP)
        self.assert_packet_not_sent_to_sgi()

    def verify_redirect(self):
        # FIXME: the IP redirect is currently also handled by the proxy
        self.send_from_access_to_sgi(b"42", remote_ip=REDIR_IP)
        self.assert_packet_sent_to_sgi(b"42", remote_ip=REDIR_TARGET_IP)

    def verify_reporting(self):
        # Access -> SGi
        self.send_from_access_to_sgi(b"42")
        self.assert_packet_sent_to_sgi(b"42")
        sr = self.if_cp.get_capture(1)[0][PFCPSessionReportRequest]
        self.assertEqual(sr[IE_ReportType].UPIR, 0)
        self.assertEqual(sr[IE_ReportType].ERIR, 0)
        self.assertEqual(sr[IE_ReportType].USAR, 1)
        self.assertEqual(sr[IE_ReportType].DLDR, 0)
        self.assertEqual(sr[IE_URR_Id].id, 1)
        self.assertEqual(sr[IE_UR_SEQN].number, 0)
        rt = sr[IE_UsageReportTrigger]
        self.assertEqual(rt.IMMER, 0)
        self.assertEqual(rt.DROTH, 0)
        self.assertEqual(rt.STOPT, 0)
        self.assertEqual(rt.START, 1)
        self.assertEqual(rt.QUHTI, 0)
        self.assertEqual(rt.TIMTH, 0)
        self.assertEqual(rt.VOLTH, 0)
        self.assertEqual(rt.PERIO, 0)
        self.assertEqual(rt.EVETH, 0)
        self.assertEqual(rt.MACAR, 0)
        self.assertEqual(rt.ENVCL, 0)
        self.assertEqual(rt.MONIT, 0)
        self.assertEqual(rt.TERMR, 0)
        self.assertEqual(rt.LIUSA, 0)
        self.assertEqual(rt.TIMQU, 0)
        self.assertEqual(rt.VOLQU, 0)
        self.assertEqual(sr[IE_UE_IP_Address].V4, 1)
        self.assertEqual(sr[IE_UE_IP_Address].V6, 0)
        self.assertEqual(sr[IE_UE_IP_Address].ipv4, self.if_access.remote_ip4)

    def verify_session_modification(self):
        send_len = 0
        for i in range(0, 3):
            send_len += self.send_from_access_to_sgi(b"42 foo bar baz")
            self.assert_packet_sent_to_sgi(b"42 foo bar baz")
        resp = self.chat(PFCPSessionModificationRequest(IE_list=[
            IE_QueryURR(IE_list=[IE_URR_Id(id=1)])
        ]), PFCPSessionModificationResponse, seid=self.cur_seid)
        self.assertEqual(CauseValues[resp[IE_Cause].cause], "Request accepted")
        # TODO: check timestamps & duration
        self.assertIn(IE_StartTime, resp)
        self.assertIn(IE_EndTime, resp)
        self.assertIn(IE_DurationMeasurement, resp)
        self.assertIn(IE_UR_SEQN, resp)
        rt = resp[IE_UsageReportTrigger]
        self.assertEqual(rt.IMMER, 1)
        self.assertEqual(rt.DROTH, 0)
        self.assertEqual(rt.STOPT, 0)
        self.assertEqual(rt.START, 0)
        self.assertEqual(rt.QUHTI, 0)
        self.assertEqual(rt.TIMTH, 0)
        self.assertEqual(rt.VOLTH, 0)
        self.assertEqual(rt.PERIO, 0)
        self.assertEqual(rt.EVETH, 0)
        self.assertEqual(rt.MACAR, 0)
        self.assertEqual(rt.ENVCL, 0)
        self.assertEqual(rt.MONIT, 0)
        self.assertEqual(rt.TERMR, 0)
        self.assertEqual(rt.LIUSA, 0)
        self.assertEqual(rt.TIMQU, 0)
        self.assertEqual(rt.VOLQU, 0)
        vm = resp[IE_VolumeMeasurement]
        self.assertTrue(vm.DLVOL)
        self.assertTrue(vm.ULVOL)
        self.assertTrue(vm.TOVOL)
        self.assertEqual(vm.total, send_len)
        self.assertEqual(vm.uplink, send_len)
        self.assertEqual(vm.downlink, 0)
        # TODO: verify more packets in both directions

    def verify_traffic_reporting(self, up_len, down_len):
        resp = self.chat(PFCPSessionModificationRequest(IE_list=[
            IE_QueryURR(IE_list=[IE_URR_Id(id=2)])
        ]), PFCPSessionModificationResponse, seid=self.cur_seid)
        vm = resp[IE_VolumeMeasurement]
        self.assertTrue(vm.DLVOL)
        self.assertTrue(vm.ULVOL)
        self.assertTrue(vm.TOVOL)
        self.assertEqual(vm.total, up_len + down_len)
        self.assertEqual(vm.uplink, up_len)
        self.assertEqual(vm.downlink, down_len)

    def tcp_handshake(self, remote_ip, remote_port):
        # 31 instead of 32 to make it a little bit easier to deal
        # with integer overflows
        s1, s2 = getrandbits(31), getrandbits(31)

        self.send_from_access_to_sgi(
            l4proto=TCP, flags="S",
            remote_ip=remote_ip, remote_port=remote_port, seq=s1, ack=0)
        self.assert_packet_sent_to_sgi(
            l4proto=TCP,
            remote_ip=remote_ip, remote_port=remote_port)

        self.send_from_sgi_to_access(
            l4proto=TCP,
            flags="SA",
            remote_ip=remote_ip, remote_port=remote_port,
            seq=s2, ack=s1+1)
        self.assert_packet_sent_to_access(
            l4proto=TCP,
            remote_ip=remote_ip, remote_port=remote_port)

        self.send_from_access_to_sgi(
            l4proto=TCP,
            flags="A",
            remote_ip=remote_ip, remote_port=remote_port,
            seq=s1+1, ack=s2+1)
        self.assert_packet_sent_to_sgi(
            l4proto=TCP,
            remote_ip=remote_ip, remote_port=remote_port)

        return s1, s2

    def verify_app_reporting_http(self):
        s1, s2 = self.tcp_handshake(remote_ip=NON_APP_RULE_IP, remote_port=80)
        http_get = b"GET / HTTP/1.1\r\nHost: example.com/\r\n\r\n"
        up_len = self.send_from_access_to_sgi(
            http_get, flags="P", l4proto=TCP,
            remote_port=80, remote_ip=NON_APP_RULE_IP, seq=s1+1, ack=s2+1)
        self.assert_packet_sent_to_sgi(
            http_get, l4proto=TCP,
            remote_port=80, remote_ip=NON_APP_RULE_IP)

        http_resp = b"HTTP/1.1 200 OK\nContent-Type: text/plain\r\n\r\nfoo"
        down_len = self.send_from_sgi_to_access(
            http_resp, l4proto=TCP, flags="A",
            remote_port=80, remote_ip=NON_APP_RULE_IP,
            seq=s2+1, ack=s1+1+len(http_get))
        self.assert_packet_sent_to_access(
            http_resp, l4proto=TCP,
            remote_port=80, remote_ip=NON_APP_RULE_IP)

        self.verify_traffic_reporting(up_len, down_len)

    def verify_app_reporting_tls(self):
        s1, s2 = self.tcp_handshake(remote_ip=NON_APP_RULE_IP_2, remote_port=443)
        tls = TLS(msg=[
            TLSClientHello(
                version=771,
                gmt_unix_time=2183047903,
                random_bytes=b"\x9f\x98\x0b\x13\x05\xa5O\xd0?\x8d\xc8\xdc)\x86\xb0W\xd7\xc1\x7f'\x19sg\x84%\xa8\xc4\xc4",
                ciphers=[
                    49200, 49196, 49192, 49188, 49172, 49162, 159, 107,
                    57, 52393, 52392, 52394, 65413, 196, 136, 129,
                    157, 61, 53, 192, 132, 49199, 49195, 49191,
                    49187, 49171, 49161, 158, 103, 51, 190, 69,
                    156, 60, 47, 186, 65, 49169, 49159, 5,
                    4, 49170, 49160, 22, 10, 255
                ],
                comp=[0],
                ext=[
                    TLS_Ext_ServerName(servernames=[
                        ServerName(nametype=0, servername=b'example.com')
                    ]),
                    TLS_Ext_SupportedPointFormat(ecpl=[0]),
                    TLS_Ext_SupportedGroups(groups=[29, 23, 24]),
                    TLS_Ext_SignatureAlgorithms(sig_algs=[
                        1537, 1539, 61423, 1281, 1283, 1025, 1027, 61166,
                        60909, 769, 771, 513, 515
                    ]),
                    TLS_Ext_ALPN(protocols=[
                        ProtocolName(protocol=b'h2'),
                        ProtocolName(protocol=b'http/1.1')
                    ])
                ])
        ], version=769)

        up_len = self.send_from_access_to_sgi(tls, flags="P", l4proto=TCP, remote_port=443, remote_ip=NON_APP_RULE_IP_2, seq=s1+1, ack=s2+1)
        self.assert_packet_sent_to_sgi(l4proto=TCP, remote_port=443, remote_ip=NON_APP_RULE_IP_2)

        down_len = self.send_from_sgi_to_access(
            l4proto=TCP, flags="A",
            remote_port=443, remote_ip=NON_APP_RULE_IP_2, seq=s2+1, ack=s1+1+len(tls))
        self.assert_packet_sent_to_access(
            l4proto=TCP,
            remote_port=443, remote_ip=NON_APP_RULE_IP_2)

        self.verify_traffic_reporting(up_len, down_len)

    def verify_app_reporting_ip(self, ip):
        # Access -> SGi (IP rule)
        up_len = self.send_from_access_to_sgi(b"42", remote_ip=ip)
        self.assert_packet_sent_to_sgi(b"42", remote_ip=ip)

        # SGi -> Access (IP rule)
        down_len = self.send_from_sgi_to_access(b"4242", remote_ip=ip)
        self.assert_packet_sent_to_access(b"4242", remote_ip=ip)

        # the following packets aren't counted
        self.send_from_access_to_sgi(b"1234567", remote_ip=NON_APP_RULE_IP_3)
        self.assert_packet_sent_to_sgi(b"1234567", remote_ip=NON_APP_RULE_IP_3)
        self.send_from_sgi_to_access(b"foobarbaz", remote_ip=NON_APP_RULE_IP_3)
        self.assert_packet_sent_to_access(b"foobarbaz", remote_ip=NON_APP_RULE_IP_3)

        self.verify_traffic_reporting(up_len, down_len)

    def verify_app_reporting(self):
        self.verify_app_reporting_http()
        self.verify_app_reporting_tls()
        self.verify_app_reporting_ip(ip=APP_RULE_IP)
        self.verify_app_reporting_ip(ip=EXTRA_SDF_IP)

# TODO: send session report response
# TODO: check for heartbeat requests from UPF
# TODO: check redirects (perhaps IPv4 type redirect) -- currently broken
# TODO: upstream the scapy changes
