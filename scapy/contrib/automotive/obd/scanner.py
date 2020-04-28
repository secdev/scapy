# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Andreas Korb <andreas.korb@e-mundo.de>
# Copyright (C) Friedrich Feigel <friedrich.feigel@e-mundo.de>
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = OnBoardDiagnosticScanner
# scapy.contrib.status = loads


from scapy.contrib.automotive.obd.obd import OBD, OBD_S03, OBD_S07, OBD_S0A, \
    OBD_S01, OBD_S06, OBD_S08, OBD_S09, OBD_NR, OBD_S02, OBD_S02_Record
from scapy.contrib.automotive.enumerator import Scanner, Enumerator
from scapy.config import conf
from scapy.themes import BlackAndWhite


class OBD_Enumerator(Enumerator):
    def scan(self, state, requests, exit_scan_on_first_negative_response=False,
             retry_if_busy_returncode=True, retries=3, timeout=1, **kwargs):
        # remove verbose from kwargs to not spam the output
        kwargs.pop("verbose", None)
        for req in requests:
            res = None
            for _ in range(retries):
                res = self.sock.sr1(req, timeout=timeout, verbose=False,
                                    **kwargs)
                if not retry_if_busy_returncode:
                    break
                elif res and res.service == 0x7f and \
                        res.response_code == 0x21:
                    continue

            self.results.append(Enumerator.ScanResult(state, req, res))
            if res and res.service == 0x7f and \
                    exit_scan_on_first_negative_response:
                break
        self.update_stats()
        self.state_completed[state] = True

    @property
    def filtered_results(self):
        return [r for r in super(OBD_Enumerator, self).filtered_results
                if r.resp.service != 0x7f]

    def show_negative_response_details(self, dump=False):
        nrs = [r.resp for r in self.results if r.resp is not None and
               r.resp.service == 0x7f]
        s = ""
        if len(nrs):
            nrcs = set([nr.response_code for nr in nrs])
            s += "These negative response codes were received " + \
                " ".join([hex(c) for c in nrcs]) + "\n"
            for nrc in nrcs:
                s += "\tNRC 0x%02x: %s received %d times" % (
                    nrc, OBD_NR(response_code=nrc).sprintf(
                        "%OBD_NR.response_code%"),
                    len([nr for nr in nrs if nr.response_code == nrc]))
                s += "\n"
        if dump:
            return s + "\n"
        else:
            print(s)

    @staticmethod
    def get_label(response,
                  positive_case="PR: PositiveResponse",
                  negative_case="NR: NegativeResponse"):
        return Enumerator.get_label(
            response, positive_case,
            response.sprintf("NR: %OBD_NR.response_code%"))


class OBD_Service_Enumerator(OBD_Enumerator):
    def get_pkts(self, p_range):
        raise NotImplementedError

    def get_supported(self, state, **kwargs):
        pkts = self.get_pkts(range(0, 0xff, 0x20))
        super(OBD_Service_Enumerator, self).scan(
            state, pkts, exit_scan_on_first_negative_response=True, **kwargs)
        supported = list()
        for _, _, r in self.filtered_results:
            dr = r.data_records[0]
            key = next(iter((dr.lastlayer().fields.keys())))
            supported += [int(i[-2:], 16) for i in
                          getattr(dr, key, ["xxx00"])]
        return [i for i in supported if i % 0x20]

    def scan(self, state, full_scan=False, **kwargs):
        if full_scan:
            supported_pids = range(0x100)
        else:
            supported_pids = self.get_supported(state, **kwargs)
        pkts = self.get_pkts(supported_pids)
        super(OBD_Service_Enumerator, self).scan(state, pkts, **kwargs)

    @staticmethod
    def print_payload(resp):
        backup_ct = conf.color_theme
        conf.color_theme = BlackAndWhite()
        load = repr(resp.data_records[0].lastlayer())
        conf.color_theme = backup_ct
        return load


class OBD_DTC_Enumerator(OBD_Enumerator):
    request = None

    def scan(self, state, full_scan=False, **kwargs):
        pkts = [self.request]
        super(OBD_DTC_Enumerator, self).scan(state, pkts, **kwargs)

    @staticmethod
    def print_payload(resp):
        backup_ct = conf.color_theme
        conf.color_theme = BlackAndWhite()
        load = repr(resp.dtcs)
        conf.color_theme = backup_ct
        return load


class OBD_S03_Enumerator(OBD_DTC_Enumerator):
    description = "Available DTCs in OBD service 03"
    request = OBD() / OBD_S03()

    @staticmethod
    def get_table_entry(tup):
        _, _, res = tup
        label = OBD_Enumerator.get_label(
            res,
            positive_case=lambda: OBD_DTC_Enumerator.print_payload(res))
        return "Service 03", "%d DTCs" % res.count, label


class OBD_S07_Enumerator(OBD_DTC_Enumerator):
    description = "Available DTCs in OBD service 07"
    request = OBD() / OBD_S07()

    @staticmethod
    def get_table_entry(tup):
        _, _, res = tup
        label = OBD_Enumerator.get_label(
            res,
            positive_case=lambda: OBD_DTC_Enumerator.print_payload(res))
        return "Service 07", "%d DTCs" % res.count, label


class OBD_S0A_Enumerator(OBD_DTC_Enumerator):
    description = "Available DTCs in OBD service 10"
    request = OBD() / OBD_S0A()

    @staticmethod
    def get_table_entry(tup):
        _, _, res = tup
        label = OBD_Enumerator.get_label(
            res,
            positive_case=lambda: OBD_DTC_Enumerator.print_payload(res))
        return "Service 0A", "%d DTCs" % res.count, label


class OBD_S01_Enumerator(OBD_Service_Enumerator):
    description = "Available data in OBD service 01"

    def get_pkts(self, p_range):
        return (OBD() / OBD_S01(pid=[x]) for x in p_range)

    @staticmethod
    def get_table_entry(tup):
        _, _, res = tup
        label = OBD_Enumerator.get_label(
            res,
            positive_case=lambda: OBD_Service_Enumerator.print_payload(res))
        return ("Service 01",
                "%s" % res.data_records[0].lastlayer().name,
                label)


class OBD_S02_Enumerator(OBD_Service_Enumerator):
    description = "Available data in OBD service 02"

    def get_pkts(self, p_range):
        return (OBD() / OBD_S02(requests=[OBD_S02_Record(pid=[x])])
                for x in p_range)

    @staticmethod
    def get_table_entry(tup):
        _, _, res = tup
        label = OBD_Enumerator.get_label(
            res,
            positive_case=lambda: OBD_Service_Enumerator.print_payload(res))
        return ("Service 02",
                "%s" % res.data_records[0].lastlayer().name,
                label)


class OBD_S06_Enumerator(OBD_Service_Enumerator):
    description = "Available data in OBD service 06"

    def get_pkts(self, p_range):
        return (OBD() / OBD_S06(mid=[x]) for x in p_range)

    @staticmethod
    def get_table_entry(tup):
        _, req, res = tup
        label = OBD_Enumerator.get_label(
            res,
            positive_case=lambda: OBD_Service_Enumerator.print_payload(res))
        return ("Service 06",
                "0x%02x %s" % (
                    req.mid[0],
                    res.data_records[0].sprintf("%OBD_S06_PR_Record.mid%")),
                label)


class OBD_S08_Enumerator(OBD_Service_Enumerator):
    description = "Available data in OBD service 08"

    def get_pkts(self, p_range):
        return (OBD() / OBD_S08(tid=[x]) for x in p_range)

    @staticmethod
    def get_table_entry(tup):
        _, req, res = tup
        label = OBD_Enumerator.get_label(
            res,
            positive_case=lambda: OBD_Service_Enumerator.print_payload(res))
        return ("Service 08",
                "0x%02x %s" % (req.tid[0],
                               res.data_records[0].lastlayer().name),
                label)


class OBD_S09_Enumerator(OBD_Service_Enumerator):
    description = "Available data in OBD service 09"

    def get_pkts(self, p_range):
        return (OBD() / OBD_S09(iid=[x]) for x in p_range)

    @staticmethod
    def get_table_entry(tup):
        _, req, res = tup
        label = OBD_Enumerator.get_label(
            res,
            positive_case=lambda: OBD_Service_Enumerator.print_payload(res))
        return ("Service 09",
                "0x%02x %s" % (req.iid[0],
                               res.data_records[0].lastlayer().name),
                label)


class OBD_Scanner(Scanner):
    default_enumerator_clss = [
        OBD_S01_Enumerator, OBD_S02_Enumerator, OBD_S06_Enumerator,
        OBD_S08_Enumerator, OBD_S09_Enumerator, OBD_S03_Enumerator,
        OBD_S07_Enumerator, OBD_S0A_Enumerator]

    def enter_state(self, state):
        return True
