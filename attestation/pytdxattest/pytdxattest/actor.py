"""
Actors package, the bussiness logic layer.
"""

import base64
import os
import logging
from abc import ABC, abstractmethod
from typing import Dict, List
from hashlib import sha384

from .rtmr import RTMR
from .tdreport import TdReport
from .tdeventlog import TDEventLogEntry, TDEventLogType, TDEventLogSpecIdHeader
from .ccel import CCEL
from .binaryblob import BinaryBlob

from ccnp import Measurement
from ccnp import MeasurementType
from ccnp import Eventlog

__author__ = "cpio"

LOG = logging.getLogger(__name__)


# pylint: disable=too-few-public-methods
class VerifyActor:
    """
    Actor to verify the RTMR
    """

    def _verify_single_rtmr(self, rtmr_index: int, rtmr_value_1: RTMR,
        rtmr_value_2: RTMR) -> None:

        if rtmr_value_1 == rtmr_value_2:
            LOG.info("RTMR[%d] passed the verification.", rtmr_index)
        else:
            LOG.error("RTMR[%d] did not pass the verification", rtmr_index)

    def verify_rtmr(self) -> None:
        """
        Fetch RTMR measurement and event logs using CCNP API and replay event log to do verification.
        """

        # 1. Check if CCEL ACPI table exist at /sys/firmware/acpi/tables/CCEL
        ccel_file = "/sys/firmware/acpi/tables/data/CCEL"
        assert os.path.exists(ccel_file), f"Could not find the CCEL file {ccel_file}"

        # 2. Check if IMA measurement event log exist at /sys/kernel/security/integrity/ima/ascii_runtime_measurements
        ima_measurement_file = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"
        assert os.path.exists(ima_measurement_file), f"Could not find the IMA measurement file {ima_measurement_file}"

        # 3. Init CCEventlogActor
        cc_event_log_actor = CCEventLogActor()

        # 4. Collect event log and replay the IMR value according to event log
        cc_event_log_actor.replay()

        # 5. Collect IMR measurements using CCNP
        rtmr_0 = Measurement.get_platform_measurement(MeasurementType.TYPE_TDX_RTMR, None, 0)
        rtmr_1 = Measurement.get_platform_measurement(MeasurementType.TYPE_TDX_RTMR, None, 1)
        rtmr_2 = Measurement.get_platform_measurement(MeasurementType.TYPE_TDX_RTMR, None, 2)
        rtmr_3 = Measurement.get_platform_measurement(MeasurementType.TYPE_TDX_RTMR, None, 3)

        # 6. Verify individual IMR value from CCNP fetching and recalculated from event log
        self._verify_single_rtmr(
            0,
            cc_event_log_actor.get_rtmr_by_index(0),
            RTMR(bytearray(base64.b64decode(rtmr_0))))

        self._verify_single_rtmr(
            1,
            cc_event_log_actor.get_rtmr_by_index(1),
            RTMR(bytearray(base64.b64decode(rtmr_1))))

        self._verify_single_rtmr(
            2,
            cc_event_log_actor.get_rtmr_by_index(2),
            RTMR(bytearray(base64.b64decode(rtmr_2))))

        self._verify_single_rtmr(
            3,
            cc_event_log_actor.get_rtmr_by_index(3),
            RTMR(bytearray(base64.b64decode(rtmr_3))))

        # 7. Verify selected digest according to file input
        # get input
        cc_event_log_actor.replay_selected_runtime_measurement()
'''
        # 2. Get the start address and length for event log area
        td_event_log_actor = TDEventLogActor(
            ccelobj.log_area_start_address,
            ccelobj.log_area_minimum_length)

        # 3. Collect event log and replay the RTMR value according to event log
        td_event_log_actor.replay()
        
        # 4. Read TD REPORT via TDCALL.GET_TDREPORT
        #td_report = TdReport.get_td_report()
        

        # 5. Verify individual RTMR value from TDREPORT and recalculated from
        #    event log
        self._verify_single_rtmr(
            0,
            td_event_log_actor.get_rtmr_by_index(0),
            RTMR(bytearray(base64.b64decode(rtmr_0))))

        self._verify_single_rtmr(
            1,
            td_event_log_actor.get_rtmr_by_index(1),
            RTMR(bytearray(base64.b64decode(rtmr_1))))

        self._verify_single_rtmr(
            2,
            td_event_log_actor.get_rtmr_by_index(2),
            RTMR(bytearray(base64.b64decode(rtmr_2))))

        self._verify_single_rtmr(
            3,
            td_event_log_actor.get_rtmr_by_index(3),
            RTMR(bytearray(base64.b64decode(rtmr_3))))
        '''

class CCEventLogActor(ABC):
    """
    Event log actor
    """

    def __init__(self):
        self._boot_time_event_logs = []
        self._run_time_event_logs = []
        self._imrs:list[RTMR] = {}
    
    def _fetch_boot_time_event_logs(self):
        # Fetch cvm boot time event log using CCNP API
        self._boot_time_event_logs = Eventlog.Get_platform_eventlog()

    def _fetch_runtime_event_logs(self):
        # Fetch cvm runtime event log from IMA
        with open('/sys/kernel/security/integrity/ima/ascii_runtime_measurements') as f:
            for line in f:
                self._run_time_event_logs.append(line)

    @staticmethod
    def _replay_single_boot_time_imr(event_logs: List[TDEventLogEntry]) -> RTMR:
        imr = bytearray(RTMR.RTMR_LENGTH_BY_BYTES)

        for event_log in event_logs:
            digest = event_log.digest
            sha384_algo = sha384()
            sha384_algo.update(imr + digest)
            imr = sha384_algo.digest()

        return RTMR(imr)

    @staticmethod
    def _replay_runtime_imr(event_logs, base: RTMR) -> RTMR:
        """
        Replay runtime measurements based on the boot time IMR
        """
        imr = bytearray(RTMR.RTMR_LENGTH_BY_BYTES)

        for event_log in event_logs:
            elements = event_log.split(" ")
            extend_val = base + elements[2]
            sha384_algo = sha384()
            sha384_algo.update(bytes.fromhex(extend_val))
            val = sha384_algo.hexdigest()

        imr = sha384_algo.digest()
        return RTMR(imr)
        
    def get_rtmr_by_index(self, index: int) -> RTMR:
        """
        Get RTMR by TD register index
        """
        return self._imrs[index]

    def replay(self) -> Dict[int, RTMR]:
        """
        Replay event logs including boot time event logs and runtime event logs to
        generate IMR values for verification
        """
        self._fetch_boot_time_event_logs()
        self._fetch_run_time_event_logs()
        
        boot_time_event_logs_by_index = {}
        for index in range(RTMR.RTMR_COUNT):
            boot_time_event_logs_by_index[index] = []

        for event_log in self._boot_time_event_logs:
            boot_time_event_logs_by_index[event_log.reg_idx].append(event_log)

        # replay boot time event logs and save replay results to dict
        imr_by_index = {}
        for imr_index, event_logs in boot_time_event_logs_by_index.items():
            imr_value = CCEventLogActor._replay_single_boot_time_rtmr(event_logs)
            imr_by_index[imr_index] = imr_value

        # runtime measurements are now extended into RTMR[2], replay the runtime event logs into RTMR[2]
        concat_imr_value = CCEventLogActor._replay_runtime_imr(self._run_time_event_logs, imr_by_index[2])
        imr_by_index[2] = concat_imr_value

        self._imrs = imr_by_index

    def replay_selected_runtime_measurement() -> str:
        return "Not Implemented"
        

# pylint: disable=too-few-public-methods
class TDEventLogActor:
    """
    Event log actor
    """

    def __init__(self, base, length):
        self._data = None
        self._log_base = base
        self._log_length = length
        self._specid_header = None
        self._event_logs = []
        self._rtmrs = {}

    def _read(self, ccel_file="/sys/firmware/acpi/tables/data/CCEL"):
        assert os.path.exists(ccel_file), f"Could not find the CCEL file {ccel_file}"
        try:
            with open(ccel_file, "rb") as fobj:
                self._data = fobj.read()
                assert len(self._data) > 0
                return self._data
        except (PermissionError, OSError):
            LOG.error("Need root permission to open file %s", ccel_file)
            return None

    @staticmethod
    def _replay_single_rtmr(event_logs: List[TDEventLogEntry]) -> RTMR:
        rtmr = bytearray(RTMR.RTMR_LENGTH_BY_BYTES)

        for event_log in event_logs:
            digest = event_log.digests[0]
            sha384_algo = sha384()
            sha384_algo.update(rtmr + digest)
            rtmr = sha384_algo.digest()

        return RTMR(rtmr)

    def get_rtmr_by_index(self, index: int) -> RTMR:
        """
        Get RTMR by TD register index
        """
        return self._rtmrs[index]

    def process(self) -> None:
        """
        Factory process raw data and generate entries
        """
        if self._specid_header is not None:
            return

        if self._read() is None:
            return

        index = 0
        count = 0
        blob = BinaryBlob(self._data, self._log_base)

        while index < self._log_length:
            start = index
            rtmr, index = blob.get_uint32(index)
            etype, index = blob.get_uint32(index)

            if rtmr == 0xFFFFFFFF:
                break

            if etype == TDEventLogType.EV_NO_ACTION:
                self._specid_header = TDEventLogSpecIdHeader(
                    self._log_base + start)
                self._specid_header.parse(self._data[start:])
                index = start + self._specid_header.length
            else:
                event_log_obj = TDEventLogEntry(self._log_base + start,
                    self._specid_header)
                event_log_obj.parse(self._data[start:])
                index = start + event_log_obj.length
                self._event_logs.append(event_log_obj)

            count += 1

    def replay(self) -> Dict[int, RTMR]:
        """
        Replay event logs to generate RTMR value, which will be used during
        verification
        """
        self.process()

        # result dictionary for classifying event logs by rtmr index
        # the key is a integer, which represents rtmr index
        # the value is a list of event log entries whose rtmr index is equal to
        # its related key
        event_logs_by_index = {}
        for index in range(RTMR.RTMR_COUNT):
            event_logs_by_index[index] = []

        for event_log in self._event_logs:
            event_logs_by_index[event_log.rtmr].append(event_log)

        rtmr_by_index = {}
        for rtmr_index, event_logs in event_logs_by_index.items():
            rtmr_value = TDEventLogActor._replay_single_rtmr(event_logs)
            rtmr_by_index[rtmr_index] = rtmr_value

        # append the IMA logs for RTMR[2]
        with open('/sys/kernel/security/integrity/ima/ascii_runtime_measurements') as f:
          val = rtmr_by_index[2].data.hex()
          for line in f:
            elements = line.split(" ")
            extend_str = val + elements[2]
            sha384_algo = sha384()
            sha384_algo.update(bytes.fromhex(extend_str))
            val = sha384_algo.hexdigest()
        rtmr2 = bytearray(RTMR.RTMR_LENGTH_BY_BYTES)
        rtmr2 = sha384_algo.digest()

        rtmr_by_index[2] = RTMR(rtmr2)

        self._rtmrs = rtmr_by_index

    def dump_td_event_logs(self) -> None:
        """
        Dump all TD event logs.
        """
        self.process()

        count, start = 0, 0

        LOG.info("==== TDX Event Log Entry - %d [0x%X] ====",
            count, self._log_base + start)
        self._specid_header.dump()
        count += 1
        start += self._specid_header.length

        for event_log in self._event_logs:
            LOG.info("==== TDX Event Log Entry - %d [0x%X] ====",
            count, self._log_base + start)
            event_log.dump()
            count += 1
            start += event_log.length

    def dump_rtmrs(self) -> None:
        """
        Dump RTMRs replayed by event log.
        """
        self.replay()

        for rtmr_index, rtmr in self._rtmrs.items():
            LOG.info("==== RTMR[%d] ====", rtmr_index)
            rtmr.dump()
            LOG.info("")
    
