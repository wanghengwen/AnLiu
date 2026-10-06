"""Offline comparison validation; no hosts, sockets or SRT library required."""
import unittest
from cmp_checks import recommended_latency, validate_lane


def logs(anl=True):
    common = ('TIMEBASE event=traffic_start event_mono_us=1 anchor_mono_lo_us=1 wall_us=2\n'
              'HEALTH state=0 input_errors=0 output_errors=0 payload_errors=0\n'
              'CMP_EXIT rc=0 elapsed_s=2\n')
    sender = common
    for fid, count in ((1, 100), (2, 60)):
        for seq in range(count):
            sender += (f'MDIAG_S {fid} {seq} 0 160 0 0 {seq}\n' if anl else
                       f'SRTS {fid} {seq} 0 160 0 0\n')
    receiver = common + ('MDIAG_R 1 0 0 160 0 100 0 0\n' if anl else 'SRTR 1 0 0 160 0 100\n')
    return sender, receiver


class ComparisonChecks(unittest.TestCase):
    def test_added_delay(self):
        self.assertEqual(recommended_latency(20, 100), 480)
        self.assertEqual(recommended_latency(20, 0), 120)
        self.assertEqual(recommended_latency(100.1, 0), 401)

    def test_complete_but_lossy(self):
        for anl in (True, False):
            self.assertEqual(validate_lane('anl' if anl else 'srt-b', 2, *logs(anl)), [])

    def test_truncated_source(self):
        s, r = logs()
        self.assertTrue(validate_lane('anl', 2, s.replace('MDIAG_S 2 59 0 160 0 0 59\n', ''), r))

    def test_duplicate_source(self):
        s, r = logs()
        self.assertTrue(validate_lane('anl', 2, s + 'MDIAG_S 1 0 0 160 0 0 0\n', r))

    def test_missing_health_or_exit(self):
        for anl in (True, False):
            s, r = logs(anl)
            name = 'anl' if anl else 'srt-b'
            self.assertTrue(validate_lane(name, 2, s, r.replace('HEALTH state=0', 'partial')))
            self.assertTrue(validate_lane(name, 2, s, r.replace('CMP_EXIT', 'partial')))
            self.assertTrue(validate_lane(name, 2, s, r.replace('rc=0', 'rc=139')))
            self.assertTrue(validate_lane(name, 2, s, r.replace('elapsed_s=2', 'elapsed_s=0')))

    def test_health_errors_and_timeouts(self):
        s, r = logs()
        self.assertTrue(validate_lane('anl', 2, s, r.replace('payload_errors=0', 'payload_errors=1')))
        self.assertTrue(validate_lane('anl', 2, s, r + 'TIMEOUT anl started=1\n'))

    def test_legacy_still_requires_complete_source(self):
        s, r = (x.replace('CMP_EXIT rc=0 elapsed_s=2\n', '') for x in logs())
        self.assertEqual(validate_lane('anl', 2, s, r, require_exit=False), [])
        self.assertTrue(validate_lane('anl', 2, s.split('MDIAG_S')[0], r, require_exit=False))


if __name__ == '__main__':
    unittest.main()
