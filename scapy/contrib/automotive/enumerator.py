# This file is part of Scapy
# See http://www.secdev.org/projects/scapy for more information
# Copyright (C) Nils Weiss <nils@we155.de>
# This program is published under a GPLv2 license

# scapy.contrib.description = Enumerator and Automotive Scanner Baseclasses
# scapy.contrib.status = loads

from collections import defaultdict, namedtuple

from scapy.error import Scapy_Exception, log_interactive, warning
from scapy.utils import make_lined_table, SingleConversationSocket
import scapy.modules.six as six
from scapy.contrib.automotive.ecu import EcuState
from scapy.contrib.automotive.scanner.graph import Graph


class Enumerator(object):
    """ Base class for Enumerators

    Args:
        sock: socket where enumeration takes place
    """
    description = "About my results"
    negative_response_blacklist = []
    ScanResult = namedtuple("ScanResult", "state req resp")

    def __init__(self, sock):
        self.sock = sock
        self.results = list()
        self.stats = {"answered": 0, "unanswered": 0, "answertime_max": 0,
                      "answertime_min": 0, "answertime_avg": 0,
                      "negative_resps": 0}
        self.state_completed = defaultdict(bool)
        self.retry_pkt = None
        self.request_iterators = dict()

    @property
    def completed(self):
        return all([self.state_completed[s] for s in self.scanned_states])

    def pre_scan(self, global_configuration):
        pass

    def scan(self, state, requests, timeout=1, **kwargs):

        if state not in self.request_iterators:
            self.request_iterators[state] = iter(requests)

        if self.retry_pkt:
            it = [self.retry_pkt]
        else:
            it = self.request_iterators[state]

        log_interactive.debug("Using iterator %s in state %s", it, state)

        for req in it:
            try:
                res = self.sock.sr1(req, timeout=timeout, verbose=False)
            except ValueError as e:
                warning("Exception in scan %s", e)
                break

            self.results.append(Enumerator.ScanResult(state, req, res))
            if self.evaluate_response(res, **kwargs):
                return

        self.update_stats()
        self.state_completed[state] = True

    def post_scan(self, global_configuration):
        pass

    def evaluate_response(self, response, **kwargs):
        return self is None  # always return False by default

    def dump(self, completed_only=True):
        if completed_only:
            selected_states = [k for k, v in self.state_completed.items() if v]
        else:
            selected_states = self.state_completed.keys()

        data = [{"state": str(s),
                 "protocol": str(req.__class__.__name__),
                 "req_time": req.sent_time,
                 "req_data": str(req),
                 "resp_time": resp.time if resp is not None else None,
                 "resp_data": str(resp) if resp is not None else None,
                 "isotp_params": {
                     "resp_src": resp.src, "resp_dst": resp.dst,
                     "resp_exsrc": resp.exsrc, "resp_exdst": resp.exdst}
                 if resp is not None else None}
                for s, req, resp in self.results if s in selected_states]

        return {"format_version": 0.1,
                "name": str(self.__class__.__name__),
                "states_completed": [(str(k), v) for k, v in
                                     self.state_completed.items()],
                "data": data}

    def remove_completed_states(self):
        selected_states = [k for k, v in self.state_completed.items() if not v]
        uncompleted_results = [r for r in self.results if
                               r.state in selected_states]
        self.results = uncompleted_results

    def update_stats(self):
        answered = self.filtered_results
        unanswered = [r for r in self.results if r.resp is None]
        answertimes = [x.resp.time - x.req.sent_time for x in answered if
                       x.resp.time is not None and x.req.sent_time is not None]
        nrs = [r.resp for r in self.filtered_results if r.resp.service == 0x7f]
        try:
            self.stats["answered"] = len(answered)
            self.stats["unanswered"] = len(unanswered)
            self.stats["negative_resps"] = len(nrs)
            self.stats["answertime_max"] = max(answertimes)
            self.stats["answertime_min"] = min(answertimes)
            self.stats["answertime_avg"] = sum(answertimes) / len(answertimes)
        except (ValueError, ZeroDivisionError):
            for k, v in self.stats.items():
                if v is None:
                    self.stats[k] = 0

    @property
    def filtered_results(self):
        return [r for r in self.results if r.resp is not None]

    @property
    def scanned_states(self):
        return set([s for s, _, _, in self.results])

    def show_negative_response_details(self, dump=False):
        raise NotImplementedError("This needs a protocol specific "
                                  "implementation")

    def show(self, dump=False, filtered=True, verbose=False):
        s = "\n\n" + "=" * (len(self.description) + 10) + "\n"
        s += " " * 5 + self.description + "\n"
        s += "-" * (len(self.description) + 10) + "\n"

        s += "%d requests were sent, %d answered, %d unanswered" % \
             (len(self.results), self.stats["answered"],
              self.stats["unanswered"]) + "\n"

        s += "Times between request and response:\tMIN: %f\tMAX: %f\tAVG: %f" \
             % (self.stats["answertime_min"], self.stats["answertime_max"],
                self.stats["answertime_avg"]) + "\n"

        s += "%d negative responses were received" % \
             self.stats["negative_resps"] + "\n"

        if not dump:
            print(s)
            s = ""
        else:
            s += "\n"

        s += self.show_negative_response_details(dump) or "" + "\n"

        if len(self.negative_response_blacklist):
            s += "The following negative response codes are blacklisted: "
            s += "%s" % self.negative_response_blacklist + "\n"

        if not dump:
            print(s)
        else:
            s += "\n"

        data = self.results if not filtered else self.filtered_results
        if len(data):
            s += make_lined_table(data, self.get_table_entry, dump=dump) or ""
        else:
            s += "=== No data to display ===\n"
        if verbose:
            completed = [(x, self.state_completed[x])
                         for x in self.scanned_states]
            s += make_lined_table(completed,
                                  lambda tup: ("Scan state completed", tup[0],
                                               tup[1]),
                                  dump=dump) or ""

        return s if dump else None

    @staticmethod
    def get_table_entry(tup):
        raise NotImplementedError()

    @staticmethod
    def get_label(response,
                  positive_case="PR: PositiveResponse",
                  negative_case="NR: NegativeResponse"):
        if response is None:
            label = "Timeout"
        elif response.service == 0x7f:
            # FIXME: service is a protocol specific field
            label = negative_case
        else:
            if isinstance(positive_case, six.string_types):
                label = positive_case
            elif callable(positive_case):
                label = positive_case()
            else:
                raise Scapy_Exception("Unsupported Type for positive_case. "
                                      "Provide a string or a function.")
        return label


class Scanner(object):
    default_enumerator_clss = []

    def __init__(self, socket, reset_handler=None, enumerators=None, **kwargs):
        # The TesterPresentSender can interfere with a enumerator, since a
        # target may only allow one request at a time.
        # The SingleConversationSocket prevents interleaving requests.
        if not isinstance(socket, SingleConversationSocket):
            self.socket = SingleConversationSocket(socket)
        else:
            self.socket = socket
        self.tps = None  # TesterPresentSender
        self.target_state = EcuState()
        self.reset_handler = reset_handler
        self.verbose = kwargs.get("verbose", False)
        if enumerators:
            # enumerators can be a mix of classes or instances
            self.enumerators = [e(self.socket) for e in enumerators if not isinstance(e, Enumerator)] + [e for e in enumerators if isinstance(e, Enumerator)]  # noqa: E501
        else:
            self.enumerators = [e(self.socket) for e in self.default_enumerator_clss]  # noqa: E501
        self.enumerator_classes = [e.__class__ for e in self.enumerators]
        self.state_graph = Graph()
        self.state_graph.add_edge((EcuState(), EcuState()))
        self.configuration = \
            {"dynamic_timeout": kwargs.pop("dynamic_timeout", False),
             "enumerator_classes": self.enumerator_classes,
             "verbose": self.verbose,
             "state_graph": self.state_graph,
             "delay_state_change": kwargs.pop("delay_state_change", 0.5)}

        for e in self.enumerators:
            self.configuration[e.__class__] = kwargs.pop(
                e.__class__.__name__ + "_kwargs", dict())

        for conf_key in self.enumerators:
            conf_val = self.configuration[conf_key.__class__]
            for kwargs_key, kwargs_val in kwargs.items():
                if kwargs_key not in conf_val.keys():
                    conf_val[kwargs_key] = kwargs_val
            self.configuration[conf_key.__class__] = conf_val

        log_interactive.debug("The following configuration was created")
        log_interactive.debug(self.configuration)

    def dump(self, completed_only=True):
        return {"format_version": 0.1,
                "enumerators": [e.dump(completed_only)
                                for e in self.enumerators],
                "state_graph": [str(p) for p in self.get_state_paths()],
                "dynamic_timeout": self.configuration["dynamic_timeout"],
                "verbose": self.configuration["verbose"],
                "delay_state_change": self.configuration["delay_state_change"]}

    def get_state_paths(self):
        paths = [Graph.dijkstra(self.state_graph, EcuState(), s)
                 for s in self.state_graph.nodes if s != EcuState()]
        return sorted([p for p in paths if p is not None] + [[EcuState()]],
                      key=lambda x: x[-1])

    def reset_target(self):
        log_interactive.info("[i] Target reset")
        self.reset_tps()
        if self.reset_handler:
            try:
                self.reset_handler(self)
            except TypeError:
                self.reset_handler()

        self.target_state = EcuState()

    def execute_enumerator(self, enumerator):
        enumerator_kwargs = self.configuration[enumerator.__class__]
        enumerator.pre_scan(self.configuration)
        enumerator.scan(state=self.target_state, **enumerator_kwargs)
        enumerator.post_scan(self.configuration)

    def reset_tps(self):
        if self.tps:
            self.tps.stop()
            self.tps = None

    def scan(self):
        scan_complete = False
        while not scan_complete:
            scan_complete = True
            log_interactive.info("[i] Scan paths %s", self.get_state_paths())
            for p in self.get_state_paths():
                log_interactive.info("[i] Scan path %s", p)
                final_state = p[-1]
                for e in self.enumerators:
                    if e.state_completed[final_state]:
                        log_interactive.debug("[+] State %s for %s completed",
                                              repr(final_state), e)
                        continue
                    if not self.enter_state_path(p):
                        log_interactive.error("[-] Error entering path %s", p)
                        continue
                    log_interactive.info("[i] EXECUTE SCAN %s for path %s",
                                         e.__class__.__name__, p)
                    self.execute_enumerator(e)
                    scan_complete = False
        self.reset_target()

    def enter_state_path(self, path):
        if path[0] != EcuState():
            raise Scapy_Exception(
                "Initial state of path not equal reset state of the target")

        self.reset_target()
        if len(path) == 1:
            return True

        for s in path[1:]:
            if not self.enter_state(s):
                return False
        return True

    def enter_state(self, state):
        raise NotImplementedError
